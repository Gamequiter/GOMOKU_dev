// threat_solver.h
//
// Threat sequence search and threat board support for 12×12 Gomoku.
//
// This module provides:
//   - Fast lookup of local threats (five, open four, simple four, open three,
//     broken three, and non-forcing threats) for each player.
//   - A solver that searches for *forcing* winning threat sequences
//     (Allis / Czajka style).
//   - Computation of defensive move sets that refute an opponent’s threat
//     sequences.
//
// Designed to sit next to the Board module (board.h) and be driven by the
// search engine. Implementation lives in threat_solver.cpp.

#ifndef GOMOKU_THREAT_SOLVER_H
#define GOMOKU_THREAT_SOLVER_H

#include <cstdint>
#include <memory>
#include <vector>

#include "board.h"

namespace gomoku {

// -----------------------------------------------------------------------------
// Basic enums used by the solver
// -----------------------------------------------------------------------------

/**
 * @brief Directions in which threats can appear.
 */
enum class Direction : uint8_t {
    Horizontal = 0,  ///< Along a row (x changes, y fixed)
    Vertical   = 1,  ///< Along a column (y changes, x fixed)
    DiagNWSE   = 2,  ///< NW–SE diagonal (\ direction)
    DiagNESW   = 3   ///< NE–SW diagonal (/ direction)
};

/**
 * @brief Threat type classification (a,b) where:
 *        a = stones towards five, b = number of ways to complete.
 *
 * The most important for search:
 *   - Five, OpenFour             => immediate / winning threats.
 *   - SimpleFour, OpenThree,
 *     BrokenThree                => forcing threats.
 *
 * Others are non-forcing but useful for evaluation.
 */
enum class ThreatType : uint8_t {
    None = 0,

    // Winning
    Five,          ///< (5,1) – existing five in a row
    OpenFour,      ///< (4,2) – two winning continuations

    // Forcing threats (opponent must respond or lose)
    SimpleFour,    ///< (4,1) – one winning continuation
    OpenThree,     ///< (3,3) – four empties, two defense points
    BrokenThree,   ///< (3,2) – three empties, three defense options

    // Non-forcing threats
    SimpleThree,   ///< (3,1)
    TwoFourWays,   ///< (2,4)
    TwoThreeWays,  ///< (2,3)
    TwoTwoWays,    ///< (2,2)
    TwoOneWay,     ///< (2,1)
    OneFiveWays,   ///< (1,5)
    OneFourWays,   ///< (1,4)
    OneThreeWays,  ///< (1,3)
    OneTwoWays,    ///< (1,2)
    OneOneWay      ///< (1,1)
};

// -----------------------------------------------------------------------------
// Threat primitives exposed to the rest of the engine
// -----------------------------------------------------------------------------

/**
 * @brief Concrete threat instance on the board for a given player.
 *
 * All coordinates are absolute board moves (0 ≤ x,y < 12).
 */
struct ThreatInstance {
    ThreatType type       = ThreatType::None;     ///< Type/strength of threat.
    Player     attacker   = Player::Black;        ///< Player that owns the threat.
    Direction  direction  = Direction::Horizontal;///< Direction of the line.

    // Stones that belong to the attacker and are part of the pattern.
    std::vector<Move> stones;

    // Empty squares that are required to remain empty for the threat to work
    // (includes defense points and auxiliary empties).
    std::vector<Move> requiredEmpty;

    // Squares where the defender can legally defend this threat.
    std::vector<Move> defensePoints;

    // Squares the attacker can later play on to convert this threat into a
    // stronger/winning threat (e.g. open-three → open-four).
    std::vector<Move> finishingMoves;
};

/**
 * @brief A forcing threat sequence for a single attacking player.
 *
 * This is a tactical line that (if valid and not refuted) should end in
 * a winning threat (Five or OpenFour).
 */
struct ThreatSequence {
    /// Player for whom this sequence is winning.
    Player attacker = Player::Black;

    /// Threats in logical order, respecting dependencies.
    std::vector<ThreatInstance> threats;

    /// Concrete moves for the attacker in this sequence (in play order).
    std::vector<Move> attackerMoves;

    /// Concrete moves for the defender in this sequence, under the
    /// “all-defenses” assumption (may contain multiple responses per threat).
    std::vector<Move> defenderMoves;
};

/**
 * @brief Result of computing defensive moves against an opponent’s threat search.
 *
 * If isLost is true, no defensive move can stop all winning sequences.
 * Otherwise, defensiveMoves lists the subset of moves that keep the position
 * alive; the search engine should focus on those moves in this node.
 */
struct DefensiveSet {
    bool isLost = false;            ///< True iff no defense exists; node is lost.
    std::vector<Move> defensiveMoves; ///< Moves that defend against all found sequences.
};

// -----------------------------------------------------------------------------
// Search-time limits / configuration
// -----------------------------------------------------------------------------

/**
 * @brief Limits and optional abort flag for a single threat search call.
 */
struct ThreatSearchLimits {
    /// Maximum number of internal nodes (threat/combo nodes) to explore.
    int maxNodes = 200000;

    /// Maximum logical depth (number of threat layers).
    int maxDepth = 20;

    /// Optional external abort flag (owned by caller). If non-null and set
    /// to true during search, the solver will stop early and return “no info”.
    const bool* abortFlag = nullptr;
};

// -----------------------------------------------------------------------------
// ThreatSolver – main OOP interface
// -----------------------------------------------------------------------------

/**
 * @brief Threat search and threat-board helper for a given root position.
 *
 * Typical usage pattern:
 *
 *   ThreatSolver solver(rootBoard);
 *
 *   // At each node in the main search:
 *   DefensiveSet ds = solver.computeDefensiveSet(rootBoard.sideToMove(), limits);
 *   if (ds.isLost) {
 *       // Node is tactically lost.
 *   } else if (!ds.defensiveMoves.empty()) {
 *       // Only consider ds.defensiveMoves in the search tree.
 *   }
 *
 * You can keep one ThreatSolver per root position and keep it in sync via
 * syncFromBoard() or the incremental onRootMove*() notifications.
 */
class ThreatSolver {
public:
    // -------------------------------------------------------------------------
    // Construction & synchronisation
    // -------------------------------------------------------------------------

    /**
     * @brief Construct a solver from an initial board position.
     *
     * Builds all internal data structures (rotated bitboards, threat board, etc.)
     * from the given Board.
     *
     * @param board Current root position.
     */
    explicit ThreatSolver(const Board& board);

    /**
     * @brief Rebuild internal state from a Board snapshot.
     *
     * Use this when the root position changes in a non-incremental way
     * (e.g. after receiving the opponent’s move from the server).
     *
     * @param board New root board state.
     */
    void syncFromBoard(const Board& board);

    /**
     * @brief Notify the solver that a new root move has been made.
     *
     * This incrementally updates internal caches around the last move.
     * Intended to be called directly after Board::makeMove().
     *
     * Example:
     *   Move m{x,y};
     *   board.makeMove(x, y);
     *   solver.onRootMoveMade(board, m);
     *
     * @param board    Board after the move has been applied.
     * @param lastMove Move that was just played at the root.
     */
    void onRootMoveMade(const Board& board, const Move& lastMove);

    /**
     * @brief Notify the solver that a root move has been undone.
     *
     * This incrementally updates internal caches around the undone move.
     * Intended to be called directly after Board::unmakeMove().
     *
     * Example:
     *   Move m{x,y};
     *   board.unmakeMove(x, y);
     *   solver.onRootMoveUndone(m);
     *
     * @param lastMove Move that was just undone at the root.
     */
    void onRootMoveUndone(const Move& lastMove);

    // -------------------------------------------------------------------------
    // Main threat sequence queries
    // -------------------------------------------------------------------------

    /**
     * @brief Search for a *forcing* winning threat sequence for a given attacker.
     *
     * Looks for sequences of threats (simple fours, open threes, broken threes,
     * etc.) that end in an OpenFour or Five and force the defender to respond
     * at each step (under Allis’s “all-defenses” assumption).
     *
     * @param attacker    Player for whom we are searching a winning sequence.
     * @param outSequence On success, filled with one found winning sequence.
     * @param limits      Search limits and optional abort flag.
     *
     * @return true if a winning sequence was found within the limits;
     *         false if no sequence was found or the search was aborted.
     *
     * Note: A false result does *not* prove that no winning sequence exists.
     *       It only means none was found under the current limits.
     */
    bool findWinningThreatSequence(Player attacker,
                                   ThreatSequence& outSequence,
                                   const ThreatSearchLimits& limits = {}) const;

    /**
     * @brief Compute the set of moves that defend against all opponent wins.
     *
     * Conceptually:
     *   1. Treat the opponent of @p defender as the attacker and search for
     *      winning threat sequences.
     *   2. If none are found, the position is tactically safe and
     *      DefensiveSet::defensiveMoves is empty.
     *   3. If at least one winning sequence is found, derive the set of moves
     *      that refute *all* such sequences (possibly empty).
     *
     * @param defender Player whose perspective we are defending.
     * @param limits   Search limits and optional abort flag.
     *
     * @return DefensiveSet describing whether the position is lost and, if not,
     *         which moves are valid defenses.
     */
    DefensiveSet computeDefensiveSet(Player defender,
                                     const ThreatSearchLimits& limits = {}) const;

    // -------------------------------------------------------------------------
    // Lightweight tactical queries (no full sequence search)
    // -------------------------------------------------------------------------

    /**
     * @brief Check if a player currently has any *immediate* winning threat.
     *
     * An “immediate winning threat” is an existing Five or OpenFour on the
     * board for @p player.
     *
     * @param player Player to test.
     * @return true if player has a Five or OpenFour already on the board.
     */
    bool hasImmediateWinningThreat(Player player) const;

    /**
     * @brief Collect all *forcing* threats currently available to a player.
     *
     * Forcing threats are:
     *   - SimpleFour
     *   - OpenThree
     *   - BrokenThree
     *
     * @param player Player for whom to collect threats.
     * @param out    Vector that will be appended with all current forcing threats.
     */
    void collectCurrentForcingThreats(Player player,
                                      std::vector<ThreatInstance>& out) const;

    /**
     * @brief Get the threat type available to @p player at @p move in one direction.
     *
     * Uses the solver’s internal threat board. If @p move is occupied or
     * no threat exists in that direction, ThreatType::None is returned.
     *
     * @param player    Player to consider as attacker.
     * @param move      Empty intersection to test.
     * @param direction Direction in which to inspect threats.
     *
     * @return Threat type in that direction for this player and move.
     */
    ThreatType getThreatAt(Player player,
                           const Move& move,
                           Direction direction) const;

    /**
     * @brief Get all four directional threat types at @p move for @p player.
     *
     * Convenience helper for evaluation.
     *
     * @param player Player to consider as attacker.
     * @param move   Empty intersection to test.
     * @param out    Vector of size 4 (one per Direction) to fill.
     *               Existing contents will be overwritten.
     */
    void getThreatsAt(Player player,
                      const Move& move,
                      std::vector<ThreatType>& out) const;

    // -------------------------------------------------------------------------
    // Rule of three: allow copying/moving as normal
    // -------------------------------------------------------------------------

    ThreatSolver(const ThreatSolver& other);
    ThreatSolver& operator=(const ThreatSolver& other);

    ThreatSolver(ThreatSolver&& other) noexcept;
    ThreatSolver& operator=(ThreatSolver&& other) noexcept;

    ~ThreatSolver();

private:
    // -------------------------------------------------------------------------
    // Pimpl to keep implementation details out of the header.
    // -------------------------------------------------------------------------

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace gomoku

#endif // GOMOKU_THREAT_SOLVER_H