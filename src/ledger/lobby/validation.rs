use super::types::{GameLobbyConfig, PlayerSeatSnapshot, ShufflerAssignment};
use crate::engine::nl::types::Chips;
use crate::ledger::GameSetupError;
use ark_ec::CurveGroup;
use std::collections::HashSet;

pub fn validate_lobby_config(cfg: &GameLobbyConfig) -> Result<(), GameSetupError> {
    if cfg.max_players <= 1 {
        return Err(GameSetupError::validation(
            "max_players must be greater than 1",
        ));
    }
    if cfg.min_players_to_start < 3 {
        return Err(GameSetupError::validation(
            "min_players_to_start must be at least 3",
        ));
    }
    if cfg.min_players_to_start > cfg.max_players {
        return Err(GameSetupError::validation(
            "min_players_to_start cannot exceed max_players",
        ));
    }
    if cfg.rake_bps < 0 {
        return Err(GameSetupError::validation("rake_bps cannot be negative"));
    }
    if cfg.buy_in == 0 {
        return Err(GameSetupError::validation(
            "buy_in must be greater than zero",
        ));
    }
    Ok(())
}

pub fn ensure_unique_seats<C: CurveGroup>(
    players: &[PlayerSeatSnapshot<C>],
) -> Result<(), GameSetupError> {
    let mut seen = HashSet::new();
    for snapshot in players {
        if !seen.insert(snapshot.seat_id) {
            return Err(GameSetupError::validation(
                "duplicate seat assignments detected",
            ));
        }
    }
    Ok(())
}

pub fn ensure_min_players<C: CurveGroup>(
    min_players: i16,
    players: &[PlayerSeatSnapshot<C>],
) -> Result<(), GameSetupError> {
    let min_required = if min_players < 3 { 3 } else { min_players } as usize;
    if players.len() < min_required {
        return Err(GameSetupError::validation(
            "not enough players to start the hand",
        ));
    }
    Ok(())
}

pub fn ensure_shuffler_sequence<C: ark_ec::CurveGroup>(
    shufflers: &[ShufflerAssignment<C>],
) -> Result<(), GameSetupError> {
    if shufflers.is_empty() {
        return Err(GameSetupError::validation(
            "at least one shuffler is required",
        ));
    }
    let mut seen = HashSet::new();
    for assignment in shufflers {
        if !seen.insert(assignment.sequence) {
            return Err(GameSetupError::validation(
                "duplicate shuffler sequence detected",
            ));
        }
    }
    Ok(())
}

pub fn ensure_buy_in<C: CurveGroup>(
    required_buy_in: Chips,
    players: &[PlayerSeatSnapshot<C>],
) -> Result<(), GameSetupError> {
    for snapshot in players {
        if snapshot.starting_stack < required_buy_in {
            return Err(GameSetupError::validation(
                "player does not meet the minimum buy-in",
            ));
        }
    }
    Ok(())
}

pub fn validate_blind_positions(
    button: u8,
    small_blind_seat: u8,
    big_blind_seat: u8,
) -> Result<(), GameSetupError> {
    if button == small_blind_seat {
        return Err(GameSetupError::validation(
            "button and small blind cannot be the same seat",
        ));
    }
    if button == big_blind_seat {
        return Err(GameSetupError::validation(
            "button and big blind cannot be the same seat",
        ));
    }
    if small_blind_seat == big_blind_seat {
        return Err(GameSetupError::validation(
            "small blind and big blind cannot be the same seat",
        ));
    }
    Ok(())
}

// NOTE: validate_commence_params has been removed.
// Validation is now done inside LobbyService::commence_game()
// after querying the stored game state.
