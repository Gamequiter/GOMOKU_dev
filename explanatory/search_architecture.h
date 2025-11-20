// search_engine.h
//
// High-level search module for a 12x12 Gomoku engine.
//
// This header only declares the search API and documents the *architecture*
// and invariants. The actual algorithms live in search_engine.cpp.
//
// The search engine is responsible for:
//   * Running an iterative-deepening Principal Variation Search (PVS) with
//     alpha-beta pruning on top of the low-level Board representation.
//   * Integrating a "Threat Solver" that performs Allis-style dependency
//     based threat-sequence search and refutation checking.
//   * Integrating a History Heuristic module for move ordering.
//   * Enforcing strict per-move time limits (with optional "panic mode").
//   * Using Board::getCandidateMoves() to keep branching factors manageable.
//
// IMPORTANT DESIGN GOALS
// ----------------------
//  1. Fast enough for tight per-move time limits on 12x12 boards.
//  2. Modular: search logic is decoupled from ThreatSolver, evaluation
//     function, and HistoryHeuristic implementation.
//  3. Safe: every makeMove() must be paired with unmakeMove(), and the
//     search must be able to terminate *immediately* on time-out.
//  4. Threat-aware: threat sequences found by ThreatSolver are treated as
//     "tactical oracles" inside the positional search.
//
// This header is heavily commented to act as a design document for the
// implementation in the .cpp file.

#ifndef GOMOKU_SEARCH_ENGINE_H
#define GOMOKU_SEARCH_ENGINE_H

#include <cstdint>
#include <vector>
#include <array>
#include <limits>
#include <chrono>

#include "board.h"   // gomoku::Board, gomoku::Move, gomoku::Player

namespace gomoku {

// Forward declarations for pluggable modules.
// ------------------------------------------
// The actual implementations can live in separate headers / .cpp files.
// The search engine only relies on the *interface* below.
//
// You are free to:
//   * Implement them as concrete classes.
//   * Implement them as adapters wrapping existing code.
//   * Extend the interfaces, as long as you keep SearchEngine code consistent.

// #############################
// ## Evaluation callback API ##
// #############################
//
// We deliberately keep evaluation decoupled from Board to allow multiple
// evaluation strategies (simple heuristic, learned model, etc.).
//
// The evaluation must be:
//   * Fast (called at leaf nodes and sometimes in quiescence).
//   * Side-aware: score is always from the perspective of "maximizing" side.
//
// CONVENTION:
//   * Positive scores are good for 'maxPlayer'.
//   * Negative scores are good for the opponent.
//   * A drawish position is close to 0.
//   * Mating scores are large in magnitude (see SearchEngine::kMateScore).
//
using EvalScore = int;
using EvalCallback = EvalScore (*)(const Board& board, Player maxPlayer);

// ##############################
// ## Threat Solver interfaces ##
// ##############################
//
// The Threat Solver encapsulates Allis-style threat sequence search and
// refutation checking described in the blog post & thesis. It serves dual
// roles:
//
//   1. ATTACK: "Given this position and attacker, is there a forcing
//      threat sequence that wins? If yes, what is the first move?"
//   2. DEFENSE: "Given this position and attacker, what moves can the
//      defender play that avoid *all* winning threat sequences?"
//
// The search engine treats ThreatSolver as an *oracle* that can:
//
//   * Prove a win for the side to move (forced win).
//   * Prove a loss (no defense exists to opponent's threats).
//   * Provide a *set of defensive moves* that must be considered when
//     the opponent has a winning attack unless refuted.
//
// Internally, your ThreatSolver will likely implement:
//   * All-defenses trick.
//   * Dependency graph of threats and combination nodes.
//   * Counter-threat / refutation search.
//   * Extraction of defensive move sets.
// See the article and Victor Allis' thesis for the core algorithms.
//
// This interface is deliberately "high-level" and hides those details.

struct ThreatAnalysis {
    // If true, 'attacker' has a forcing winning sequence assuming optimal
    // defense (i.e. the position is tactically lost for the defender).
    bool attackerHasForcedWin = false;

    // First move of a winning threat sequence for the attacker.
    // Valid only if attackerHasForcedWin == true.
    //
    // NOTE: For the search engine, we *usually only need the first move*.
    // The full sequence is valuable for debugging and optional PV printing.
    Move firstWinningMove;

    // Optional: entire sequence of moves in the winning line, for debugging,
    // principal variation annotation, or engine output.
    std::vector<Move> winningLine;

    // The set of defender moves that *jointly* defend against all threat
    // sequences discovered for the attacker.
    //
    // If attackerHasForcedWin == true:
    //   * If defensiveMoves is empty: position is proven lost for defender.
    //   * If defensiveMoves is non-empty: defender can still hold if he
    //     plays within this set.
    //
    // If attackerHasForcedWin == false:
    //   * defensiveMoves may be empty or contain "interesting" moves, but
    //     search engine is free to ignore it or treat it as a soft hint.
    std::vector<Move> defensiveMoves;
};

// Abstract threat solver API. Implementation is injected into SearchEngine.
class IThreatSolver {
public:
    virtual ~IThreatSolver() = default;

    // Analyze threats for 'attacker' on the given board.
    //
    // Implementor responsibilities:
    //   * Must NOT modify 'board'.
    //   * Must be deterministic for the same board hashKey().
    //   * Should exploit the board's internal threat boards / rotated
    //     bitboards, if available, for speed.
    //
    // Performance expectations:
    //   * This will be called in every non-terminal search node.
    //   * Must be carefully optimized and memoized (e.g. by hashKey)
    //     to avoid redundant work.
    virtual ThreatAnalysis analyzeThreats(const Board& board,
                                          Player attacker) = 0;
};

// ##################################
// ## History Heuristic interfaces ##
// ##################################
//
// This encapsulates the history heuristic and any related move-ordering
// data structures (killer moves, counter-moves, quiet-move history, etc.).
//
// The SearchEngine will:
//   * Query history scores to order candidate moves.
//   * Update history when a move causes a beta-cutoff, or appears in the PV.

class IHistoryHeuristic {
public:
    virtual ~IHistoryHeuristic() = default;

    // Return a heuristic score for a move (larger = more promising).
    //
    // Notes:
    //   * The implementation can choose any internal scale.
    //   * Typical implementations store statistics indexed by
    //     (player, move.x, move.y, depth bucket, etc.).
    virtual int getHistoryScore(Player player, const Move& move) const = 0;

    // Called when a move causes a beta cutoff at some depth.
    //
    // Implementations typically:
    //   * Increase the history value for (player, move).
    //   * Possibly decay or age older entries.
    virtual void recordBetaCutoff(Player player,
                                  const Move& move,
                                  int depth) = 0;

    // Optional: called for PV moves at each depth to slightly boost them.
    virtual void recordPVMove(Player player,
                              const Move& move,
                              int depth) = 0;

    // Utility: allow the search engine to clear history between games.
    virtual void clear() = 0;
};

// #############################
// ## Search engine interface ##
// #############################

// The SearchEngine owns the search state for a single game. It is NOT
// thread-safe; you should create one instance per thread if you want
// parallel search (not covered in this design).
class SearchEngine {
public:
    // Constants used across the search implementation.
    // These are chosen to leave room between evaluation scores and
    // mate scores.
    static constexpr EvalScore kInfinity   = std::numeric_limits<EvalScore>::max() / 4;
    static constexpr EvalScore kMateScore  = kInfinity - 1000;  // Score for immediate win.
    static constexpr EvalScore kDrawScore  = 0;

    // Search limits control how far and how long search is allowed to go.
    // These are passed per-move to searchBestMove().
    struct SearchLimits {
        // Maximum search depth in plies (half-moves).
        // Set to a reasonably large number (e.g. 32) and rely on time limits
        // + pruning to keep search manageable.
        int maxDepth = 32;

        // Hard cap on nodes visited. Use 0 to disable node-based stopping.
        std::uint64_t maxNodes = 0;

        // Soft per-move time limit (milliseconds). The engine should aim
        // to return before this expires.
        std::uint64_t timeLimitMs = 1000;

        // Optional additional margin for "panic mode". If panic mode is
        // enabled, the engine may slightly exceed timeLimitMs (up to this
        // extra margin) while trying to escape a discovered losing PV.
        std::uint64_t panicExtraTimeMs = 300;

        // Whether null-move forward pruning is enabled. Should be enabled
        // by default, but can be disabled for debugging.
        bool enableNullMove = true;

        // Whether to use "panic mode" as described in the blog post:
        // when the current best move is found to be losing at depth N+1,
        // keep searching alternative root moves even if the time limit
        // is exceeded, up to panicExtraTimeMs.
        bool enablePanicMode = true;
    };

    // Detailed result of a single move search.
    struct SearchResult {
        Move       bestMove;         // Selected root move.
        EvalScore  bestScore = 0;    // Score from perspective of sideToMove at root.
        int        depthReached = 0; // Deepest fully completed iteration.
        bool       isMate = false;   // True if bestScore indicates a forced win/loss.
        bool       isTimeout = false;// True if search stopped due to time.
        bool       isForcedWin = false; // True if ThreatSolver proved a win at root.

        // The principal variation (PV) line from root:
        //   sideToMove: pv[0], opponent: pv[1], ...
        std::vector<Move> principalVariation;

        // Node statistics (for logging / tuning).
        std::uint64_t nodes = 0;
        std::uint64_t qnodes = 0; // nodes visited in quiescence (if used)
        std::uint64_t hashHits = 0;
    };

    // SearchEngine constructor:
    //
    // Arguments:
    //   * board     - The current game position. SearchEngine operates
    //                 directly on this reference via makeMove/unmakeMove.
    //   * evaluator - Evaluation function pointer. Must be fast and side-aware.
    //   * threatSolver    - Threat oracle implementing Allis-style search.
    //   * historyHeuristic - Move ordering helper.
    //
    // Lifetime & ownership:
    //   * SearchEngine DOES NOT own board or the injected modules; they must
    //     outlive the SearchEngine.
    SearchEngine(Board&             board,
                 EvalCallback       evaluator,
                 IThreatSolver*     threatSolver,
                 IHistoryHeuristic* historyHeuristic);

    // Top-level entry point: compute the best move from the current board
    // position within the given limits.
    //
    // Typical implementation steps:
    //   1. Initialize internal timers and counters.
    //   2. Probe ThreatSolver at root for an immediate forced-win:
    //        - If sideToMove has attackerHasForcedWin and either:
    //            * defensiveMoves is empty, or
    //            * the engine policy trusts the ThreatSolver fully,
    //          then immediately return firstWinningMove as the best move
    //          and mark isForcedWin=true.
    //   3. If not a trivial forced win, run iterative deepening:
    //        for depth = 1 .. limits.maxDepth:
    //          - Run a PVS/alpha-beta search to 'depth'.
    //          - Store best move and PV from that iteration.
    //          - Periodically check time and node limits.
    //          - If time is nearly exhausted, break.
    //   4. If panic mode is enabled and the last completed depth found
    //      that the current best move loses (e.g. mate in N for the
    //      opponent), enter panic mode:
    //          - Continue searching *only alternative root moves* to try
    //            to find a non-losing move, even if timeLimitMs is exceeded,
    //            but stop when panicExtraTimeMs is consumed or all root
    //            moves have been checked.
    //
    // The function returns the best SearchResult computed up to the point
    // where limits or panic mode required stopping.
    SearchResult searchBestMove(const SearchLimits& limits);

    // Optional: expose statistics from the last search.
    const SearchResult& getLastSearchResult() const { return lastResult_; }

    // Optional: clear transposition table between games (if implemented).
    void clearTranspositionTable();

private:
    // ###########################
    // ## Internal data members ##
    // ###########################

    Board&          board_;
    EvalCallback    eval_;
    IThreatSolver*  threatSolver_;
    IHistoryHeuristic* history_;

    // Root side to move for the *current* search. We pin this at the start
    // of searchBestMove() and pass it down implicitly via evaluation so that:
    //   * Scores are always measured from rootSide_'s perspective.
    //   * ThreatSolver can be queried for either player, but evaluation
    //     is always mapped to this fixed frame of reference.
    Player          rootSide_;

    // Timing and node counters.
    using Clock = std::chrono::steady_clock;
    Clock::time_point startTime_;
    SearchLimits   limits_;
    std::uint64_t  nodes_ = 0;
    std::uint64_t  qnodes_ = 0;
    std::uint64_t  hashHits_ = 0;
    bool           stop_ = false;  // Global stop flag checked in every node.

    // Last completed search result. Used by searchBestMove() and for
    // external inspection/logging.
    SearchResult   lastResult_;

    // ===========================
    // == Transposition table  ==
    // ===========================
    //
    // A standard Zobrist-Hash based TT keyed by Board::getHashKey().
    //
    // Key design points:
    //   * Must handle "mate distance" correctly: stored mate scores should
    //     be normalized so that they can be re-based on the current ply.
    //   * Must distinguish between EXACT / LOWERBOUND / UPPERBOUND entries.
    //   * Depth: store search depth (in plies) to indicate how strong the
    //     bound is; do not overwrite deeper entries with shallower ones.
    //
    // The implementation details (hash table size, replacement scheme,
    // concurrency) live in the .cpp. Here we just define the interface
    // used inside SearchEngine.

    enum class TTNodeType : std::uint8_t {
        Exact,       // Exact score.
        LowerBound,  // alpha-beta lower bound (score >= value).
        UpperBound   // alpha-beta upper bound (score <= value).
    };

    struct TTEntry {
        std::uint64_t key = 0;   // Zobrist hash from Board::getHashKey().
        EvalScore     value = 0; // Normalized score (see implementation).
        EvalScore     eval = 0;  // Optional: raw static evaluation at node.
        int           depth = -1;// Search depth in plies.
        TTNodeType    type = TTNodeType::Exact;
        Move          bestMove;  // Move that produced this value (if any).
    };

    // Underlying TT storage: fixed-size array or hash-table.
    // The concrete container is defined in the .cpp.
    //
    // Pitfalls to watch out for:
    //   * Collisions: we only trust entry if entry.key == current key.
    //   * Replacement policy: good default is "always replace shallow depth",
    //     or a 2-way associative cluster.
    //   * Thread safety: in single-thread engine, this can be a raw array
    //     without locks; parallel search requires proper synchronization.
    std::vector<TTEntry> tt_;

    // TT helper methods (declared, implemented in .cpp).
    TTEntry* probeTT(std::uint64_t key);
    void     storeTT(std::uint64_t key,
                     EvalScore     value,
                     EvalScore     eval,
                     int           depth,
                     TTNodeType    type,
                     const Move&   bestMove);

    // Normalize mate scores when storing/loading from TT:
    //   * When storing, convert "mate in N" to a canonical form independent
    //     of the current ply.
    //   * When reading, convert back to a ply-relative score.
    //
    // This avoids TT collisions between same position reached at different
    // depths from the root.
    static EvalScore toTTScore(EvalScore score, int plyFromRoot);
    static EvalScore fromTTScore(EvalScore score, int plyFromRoot);

    // #############################
    // ## Core search entrypoints ##
    // #############################

    // Single-depth PVS alpha-beta search.
    //
    // Parameters:
    //   depth      - Remaining search depth (in plies) from this node.
    //   alpha,beta - Alpha-beta bounds (from rootSide_ perspective).
    //   ply        - Distance from root (for mate score normalization).
    //   allowNull  - Whether null-move pruning is allowed in this node.
    //   inPV       - Whether this node is in the current principal variation.
    //
    // Return:
    //   Score from rootSide_ perspective.
    //
    // IMPORTANT IMPLEMENTATION NOTES:
    //   * Must check the global 'stop_' flag at regular intervals, and
    //     return immediately if set (propagating a "best available" score).
    //   * Must handle terminal conditions:
    //       - Win/loss on the board (Board::checkWin()).
    //       - No legal moves (draw or loss depending on rules).
    //   * Must integrate ThreatSolver as described:
    //       - analyzeThreats(board, sideToMove) and analyzeThreats(board, opponent).
    //       - If opponent has forced win with no defensiveMoves => current node is
    //         a theoretical loss; score as -kMateScore + ply.
    //       - If sideToMove has forced win (attack) with empty defensiveMoves for
    //         opponent => theoretical win; score as +kMateScore - ply.
    //       - If opponent has forced win but has defensiveMoves, restrict the
    //         child move list to those defensive moves only.
    //   * Must use Board::getCandidateMoves() to generate a limited move set
    //     when not restricted by threat defenses.
    EvalScore search(int depth,
                     EvalScore alpha,
                     EvalScore beta,
                     int       ply,
                     bool      allowNull,
                     bool      inPV);

    // Quiescence search (optional but recommended).
    //
    // In Gomoku, the analogue of "captures/checks only" is "forcing tactical
    // moves only" (moves that create or resolve threats like open three/four).
    //
    // Implementation idea:
    //   * Stand pat: evaluate current position.
    //   * If stand-pat >= beta: return beta (cutoff).
    //   * Generate only tactical candidate moves (e.g. those that create
    //     or defend important threats per ThreatSolver / Board).
    //   * Recurse with depth == 0 (or small depth).
    //   * This avoids horizon effects where the engine fails to see an
    //     immediate threat one ply beyond nominal depth.
    EvalScore quiescence(EvalScore alpha,
                         EvalScore beta,
                         int       ply);

    // Iterative deepening driver. This is called by searchBestMove().
    //
    // Responsibilities:
    //   * For depth=1..maxDepth:
    //       - Run search(depth, ...).
    //       - Update root best move and PV.
    //       - Implement aspiration windows around previous iteration's score:
    //           alpha = prevScore - window, beta = prevScore + window.
    //       - If score is outside window, re-search with full window.
    //   * Monitor time / nodes and set 'stop_' when limits are hit.
    //   * Detect losing PV at new depth and trigger panic-mode if allowed.
    void iterativeDeepening();

    // #########################
    // ## Move ordering & PV  ##
    // #########################

    // Generate moves at the current node.
    //
    // Implementation must:
    //   * If there is a list of forced defensive moves from ThreatSolver
    //     for the side to move, return that list (intersected with legal moves).
    //   * Otherwise:
    //       - Use Board::getCandidateMoves() to get spatially relevant moves.
    //       - Optionally add other high-value moves if ThreatSolver suggests them.
    //   * Remove illegal moves (isOccupied()) as a safety net.
    //
    // PERF NOTE:
    //   * This should NOT allocate in hot paths if possible. Reuse static
    //     buffers or thread-local vectors, or use a pool managed in the .cpp.
    std::vector<Move> generateMoves(const ThreatAnalysis& threatDefForSideToMove);

    // Sort moves in-place by descending promise.
    //
    // Heuristics to combine:
    //   * PV move from TT / previous iteration first.
    //   * Moves returned as part of winning threat sequences or critical
    //     defenses first.
    //   * History Heuristic score (getHistoryScore).
    //   * Killer moves / counter-moves (if stored by this class).
    //
    // Implementation detail:
    //   * For performance, prefer a simple scoring pass + std::sort or
    //     partial sort.
    void orderMoves(Player             sideToMove,
                    std::vector<Move>& moves,
                    const Move&        ttMove,
                    const Move&        pvMove,
                    const ThreatAnalysis& threatInfo);

    // After each root iteration we extract the PV line by following best moves
    // from the TT, starting at root, until:
    //   * No TT entry, or
    //   * Move is illegal (safety break), or
    //   * Depth limit.
    //
    // This function is called by iterativeDeepening() to fill lastResult_.principalVariation.
    void extractPrincipalVariation(std::vector<Move>& outPV, int maxDepth);

    // #################################
    // ## Null-move forward pruning   ##
    // #################################
    //
    // Null move heuristic:
    //   * If the side to move is not in immediate tactical danger (no
    //     opponent forced win according to ThreatSolver) and depth is
    //     sufficiently large, we may try a "null move":
    //       - Temporarily give the move to the opponent without making
    //         a real move (conceptual "pass") by toggling side_to_move.
    //       - Search with reduced depth (depth - R).
    //   * If the null-move search returns a value >= beta, we assume the
    //     position is too good for the side to move and perform a cutoff.
    //
    // IMPORTANT: Avoid null moves in:
    //   * Positions with immediate tactical threats (threatDefForSideToMove
    //     shows opponent has forced win, etc.).
    //   * Very shallow depths.
    //   * Repeated null moves in a row (avoid "zugzwang" pitfalls, rare in
    //     Gomoku but still).
    bool canDoNullMove(const ThreatAnalysis& threatInfo,
                       int                   depth,
                       int                   ply) const;

    EvalScore nullMoveSearch(EvalScore alpha,
                             EvalScore beta,
                             int       depth,
                             int       ply);

    // ####################################
    // ## Time management & stop checks  ##
    // ####################################

    // Check whether we should abort search due to time/node limits.
    //
    // Implementation must:
    //   * Called periodically (e.g., every N nodes) to check:
    //       - nodes_ >= limits_.maxNodes (if set)
    //       - elapsedTime >= limits_.timeLimitMs (unless in panic mode)
    //   * Sets stop_ = true if either limit is exceeded.
    //
    // NOTE:
    //   * In panic mode, we may treat timeLimitMs as soft and only stop
    //     when elapsed > timeLimitMs + panicExtraTimeMs. This logic lives
    //     here to keep search() internals simple.
    void checkStopCondition();

    // Convenience to compute elapsed milliseconds since start of search.
    std::uint64_t elapsedMs() const;

    // #################################
    // ## RAII helpers for make/unmake ##
    // #################################
    //
    // Correct pairing of makeMove/unmakeMove is critical. A subtle early
    // return in search() can corrupt the board and cause non-deterministic
    // bugs that are extremely hard to debug.
    //
    // To reduce risk, we provide a small RAII helper that automatically
    // unmakes a move when it goes out of scope.
    //
    // Usage:
    //   {
    //       MoveGuard guard(board_, move);
    //       if (!guard.isValid()) continue;  // illegal move
    //       // ... recurse ...
    //   } // move automatically unmade here
    //
    class MoveGuard {
    public:
        MoveGuard(Board& board, const Move& move)
            : board_(board), move_(move), valid_(board_.makeMove(move.x, move.y)) {}

        ~MoveGuard() {
            if (valid_) {
                board_.unmakeMove(move_.x, move_.y);
            }
        }

        bool isValid() const { return valid_; }

    private:
        Board& board_;
        Move   move_;
        bool   valid_;
    };

}; // class SearchEngine

} // namespace gomoku

#endif // GOMOKU_SEARCH_ENGINE_H