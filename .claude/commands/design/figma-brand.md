---
description: Extract brand assets (colors, logo, fonts) from Figma and generate Tailwind tokens.
argument-hint: [node-id]
---
Use the frontend-designer subagent to extract LegitPoker brand assets from Figma.

**What it does:**
1. Retrieves design variables and code from the specified Figma node (or current selection)
2. Extracts:
   - **Color palette** (brand colors, neutrals, semantic colors)
   - **Logo assets** (SVG/PNG exports, sizing guidelines)
   - **Typography** (font families, weights, sizes, line heights)
   - **Other tokens** (spacing, border radius, shadows)
3. Generates `styles/theme.css` with Tailwind v4 `@theme` tokens
4. Creates usage documentation with examples

**Target node:** $ARGUMENTS (leave empty for current selection)

The subagent will create:
- `styles/theme.css` - Tailwind v4 theme configuration
- `docs/design/brand-guide.md` - Brand asset reference
- Component usage examples
