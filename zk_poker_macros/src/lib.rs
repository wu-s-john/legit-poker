use proc_macro::TokenStream;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{
    parse_macro_input, spanned::Spanned, Expr, ExprLit, FnArg, ItemFn, Lit, LitStr, Meta, Pat,
    Token,
};

struct TrackArgs {
    operation: Option<LitStr>,
    target: Option<LitStr>,
}

impl Parse for TrackArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let metas: Punctuated<Meta, Token![,]> = Punctuated::parse_terminated(input)?;
        let mut operation: Option<LitStr> = None;
        let mut target: Option<LitStr> = None;
        for meta in metas {
            match meta {
                Meta::NameValue(nv) => {
                    let value_span = nv.value.span();
                    let key = nv.path;
                    match (key.is_ident("operation"), key.is_ident("target")) {
                        (true, _) => {
                            if let Expr::Lit(ExprLit {
                                lit: Lit::Str(s), ..
                            }) = nv.value
                            {
                                operation = Some(s);
                            } else {
                                return Err(syn::Error::new(
                                    value_span,
                                    "operation must be a string literal",
                                ));
                            }
                        }
                        (_, true) => {
                            if let Expr::Lit(ExprLit {
                                lit: Lit::Str(s), ..
                            }) = nv.value
                            {
                                target = Some(s);
                            } else {
                                return Err(syn::Error::new(
                                    value_span,
                                    "target must be a string literal",
                                ));
                            }
                        }
                        _ => {
                            return Err(syn::Error::new(
                                key.span(),
                                "expected `operation = \"...\"` or `target = \"...\"`",
                            ));
                        }
                    }
                }
                Meta::Path(p) => {
                    return Err(syn::Error::new(
                        p.span(),
                        "expected `operation = \"...\"` or `target = \"...\"`",
                    ))
                }
                Meta::List(l) => {
                    return Err(syn::Error::new(
                        l.span(),
                        "expected `operation = \"...\"` or `target = \"...\"`",
                    ))
                }
            }
        }
        Ok(Self { operation, target })
    }
}

/// Attribute macro to track constraints/witness deltas around a function body.
///
/// Usage:
///   #[track_constraints]                       // defaults: target = "r1cs", operation = module::file::fn
///   #[track_constraints(target = "r1cs")]     // custom target, default operation
///   #[track_constraints(operation = "...", target = "...")]  // both custom
#[proc_macro_attribute]
pub fn track_constraints(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as TrackArgs);
    let operation = args.operation;
    let target = args.target;

    let func = parse_macro_input!(item as ItemFn);
    let fn_name = func.sig.ident.clone();

    // Require free functions: first parameter must be a typed identifier (e.g., `cs`).
    let cs_ident: syn::Ident = match func.sig.inputs.first() {
        Some(FnArg::Typed(pat_type)) => match &*pat_type.pat {
            Pat::Ident(p) => p.ident.clone(),
            _ => {
                return syn::Error::new(
                    pat_type.pat.span(),
                    "#[track_constraints] expects the first parameter to be the constraint system (e.g., `cs`). For methods, use #[track_constraints_impl].",
                )
                .to_compile_error()
                .into()
            }
        },
        Some(FnArg::Receiver(_)) => {
            return syn::Error::new(
                func.sig.span(),
                "#[track_constraints] does not support methods. Use #[track_constraints_impl].",
            )
            .to_compile_error()
            .into()
        }
        None => {
            return syn::Error::new(
                func.sig.span(),
                "#[track_constraints] requires at least one parameter (the constraint system).",
            )
            .to_compile_error()
            .into()
        }
    };

    wrap_function(func, cs_ident, operation, target, fn_name)
}

#[proc_macro_attribute]
pub fn track_constraints_impl(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as TrackArgs);
    let operation = args.operation;
    let target = args.target;

    let func = parse_macro_input!(item as ItemFn);
    let fn_name = func.sig.ident.clone();

    // Methods: pick the first typed identifier parameter, skipping any receiver.
    let cs_ident: syn::Ident = match func
        .sig
        .inputs
        .iter()
        .find_map(|arg| match arg {
            FnArg::Typed(pat_type) => match &*pat_type.pat {
                Pat::Ident(p) => Some(p.ident.clone()),
                _ => None,
            },
            FnArg::Receiver(_) => None,
        }) {
        Some(id) => id,
        None => {
            return syn::Error::new(
                func.sig.span(),
                "#[track_constraints_impl] could not find a typed parameter for the constraint system (e.g., `cs`).",
            )
            .to_compile_error()
            .into()
        }
    };

    wrap_function(func, cs_ident, operation, target, fn_name)
}

fn wrap_function(
    mut func: ItemFn,
    cs_ident: syn::Ident,
    operation: Option<LitStr>,
    target: Option<LitStr>,
    fn_name: syn::Ident,
) -> TokenStream {
    let op_tokens = if let Some(s) = operation {
        quote!(#s)
    } else {
        quote!(::core::concat!(
            ::core::module_path!(),
            "::",
            ::core::file!(),
            "::",
            stringify!(#fn_name)
        ))
    };
    let target_tokens = if let Some(s) = target {
        quote!(#s)
    } else {
        quote!("r1cs")
    };

    let orig_block = func.block.clone();
    let new_block_ts = quote!({
        let __tc_cs_for_counters = #cs_ident.clone();
        let __tc_initial_constraints = __tc_cs_for_counters.num_constraints();
        let __tc_initial_witnesses = __tc_cs_for_counters.num_witness_variables();

        let __tc_result = (|| #orig_block)();

        let __tc_added_constraints = __tc_cs_for_counters.num_constraints() - __tc_initial_constraints;
        let __tc_added_witnesses = __tc_cs_for_counters.num_witness_variables() - __tc_initial_witnesses;

        ::tracing::info!(
            target: #target_tokens,
            operation = #op_tokens,
            constraints_added = __tc_added_constraints,
            witnesses_added = __tc_added_witnesses,
            "Constraint tracking"
        );

        __tc_result
    });

    match syn::parse2(new_block_ts) {
        Ok(block) => {
            func.block = block;
            quote!(#func).into()
        }
        Err(e) => e.to_compile_error().into(),
    }
}
