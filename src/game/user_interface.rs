//! User interface utilities for interactive gameplay

use std::io::{self, Write};
use crate::player_service::PlayerAction;

/// Card suits for display
const SUITS: [&str; 4] = ["♠", "♥", "♦", "♣"];

/// Card ranks for display
const RANKS: [&str; 13] = ["2", "3", "4", "5", "6", "7", "8", "9", "10", "J", "Q", "K", "A"];

/// Convert a card value (0-51) to a readable string
pub fn format_card(card_value: u8) -> String {
    if card_value >= 52 {
        return "??".to_string();
    }
    let rank = (card_value % 13) as usize;
    let suit = (card_value / 13) as usize;
    format!("{}{}", RANKS[rank], SUITS[suit])
}

/// Format multiple cards for display
pub fn format_cards(cards: &[u8]) -> String {
    cards.iter()
        .map(|&c| format_card(c))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Display cards with a label
pub fn display_cards(label: &str, cards: &[u8]) {
    println!("🎴 {}: [{}]", label, format_cards(cards));
}

/// Prompt user for initial wager amount
pub fn prompt_for_wager(max_amount: u64) -> Result<u64, Box<dyn std::error::Error>> {
    println!("\n💰 INITIAL WAGER");
    println!("{}", "-".repeat(40));
    println!("Your current balance: {} chips", max_amount);
    
    loop {
        print!("How much would you like to wager? (10-{}): ", max_amount);
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        match input.trim().parse::<u64>() {
            Ok(amount) if amount >= 10 && amount <= max_amount => {
                println!("✅ You wagered {} chips", amount);
                return Ok(amount);
            }
            Ok(_) => {
                println!("❌ Invalid amount. Please enter between 10 and {} chips.", max_amount);
            }
            Err(_) => {
                println!("❌ Invalid input. Please enter a number.");
            }
        }
    }
}

/// Prompt user for betting action
pub fn prompt_for_betting_action(
    current_pot: u64,
    min_bet: u64,
    player_balance: u64,
    phase: &str,
) -> Result<PlayerAction, Box<dyn std::error::Error>> {
    println!("\n🎯 {} - YOUR TURN", phase);
    println!("{}", "-".repeat(40));
    println!("Current pot: {} chips", current_pot);
    println!("Minimum bet to call: {} chips", min_bet);
    println!("Your balance: {} chips", player_balance);
    println!("\nOptions:");
    println!("  1. Fold (forfeit the hand)");
    println!("  2. Call (match the minimum bet: {} chips)", min_bet);
    
    if player_balance > min_bet {
        println!("  3. Raise (bet more than minimum)");
    }
    
    loop {
        print!("\nYour choice (1-3): ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        
        match input.trim() {
            "1" => {
                println!("😔 You folded.");
                return Ok(PlayerAction::Fold);
            }
            "2" => {
                if player_balance >= min_bet {
                    println!("📞 You called {} chips.", min_bet);
                    return Ok(PlayerAction::Call);
                } else {
                    println!("❌ Insufficient balance to call. You must fold.");
                    return Ok(PlayerAction::Fold);
                }
            }
            "3" if player_balance > min_bet => {
                loop {
                    print!("Enter raise amount ({}-{}): ", min_bet + 1, player_balance);
                    io::stdout().flush()?;
                    
                    let mut raise_input = String::new();
                    io::stdin().read_line(&mut raise_input)?;
                    
                    match raise_input.trim().parse::<u64>() {
                        Ok(amount) if amount > min_bet && amount <= player_balance => {
                            println!("💪 You raised to {} chips!", amount);
                            return Ok(PlayerAction::Raise(amount));
                        }
                        Ok(_) => {
                            println!("❌ Invalid amount. Must be between {} and {}.", 
                                   min_bet + 1, player_balance);
                        }
                        Err(_) => {
                            println!("❌ Invalid input. Please enter a number.");
                        }
                    }
                }
            }
            _ => {
                println!("❌ Invalid choice. Please enter 1, 2, or 3.");
            }
        }
    }
}

/// Display game header
pub fn display_game_header() {
    println!("\n{}", "=".repeat(80));
    println!("🎮 ZK POKER - INTERACTIVE GAME");
    println!("{}", "=".repeat(80));
}

/// Display phase header
pub fn display_phase(phase: &str) {
    println!("\n📍 {}", phase);
    println!("{}", "-".repeat(40));
}

/// Display winner announcement
pub fn display_winner(winner: &str, pot: u64, is_human: bool) {
    println!("\n{}", "=".repeat(80));
    println!("🏆 GAME RESULT");
    println!("{}", "=".repeat(80));
    
    if is_human {
        println!("🎉 CONGRATULATIONS! You won {} chips!", pot);
    } else {
        println!("😔 {} wins the pot of {} chips.", winner, pot);
        println!("Better luck next time!");
    }
}

/// Wait for user to continue
pub fn wait_for_continue() -> Result<(), Box<dyn std::error::Error>> {
    print!("\nPress Enter to continue...");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(())
}