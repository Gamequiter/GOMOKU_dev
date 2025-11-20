// threat_solver.h
//
// Threat sequence search for 12×12 Gomoku.
//
// This module is responsible for the *tactical* layer of the engine:
//   - Detecting winning / forcing threat sequences (fives, open fours, simple fours,
//     open threes, broken threes) using Victor Allis–style “all-defenses” and
//     dependency-based search.  [oai_citation:0‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//   - Enumerating all winning sequences for the attacker (if any).
//   - Computing the *set of defensive moves* for the defender that neutralize
//     *all* winning sequences, used to prune the main alpha–beta search.  [oai_citation:1‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
// ThreatSolver *does not* own or modify the main game tree Board; it works on
// copies and on its own internal bitboards. The Search Engine is expected to:
//
//   - Keep a single Board instance representing the current node.
//   - Call ThreatSolver when it needs:
//       * “Does side X have a forcing win (threat sequence) here?”
//       * “If the opponent has a threat sequence, what moves defend against it?”
//
// The Board class (board.h) is intentionally minimal; it does not expose rotated
// bitboards or threat boards. ThreatSolver therefore maintains its own:
//
//   - Rotated bitboards (H, V, two diagonals) for fast line extraction.
//   - Threat boards for each player, updated incrementally around last move.
//   - Precomputed 1-D threat pattern lookup tables for fast pattern recognition
//     along lines, as described in the reference article.  [oai_citation:2‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
// NOTE: This header is intentionally *heavily commented* and architecturally biased.
//       The .cpp file will contain the actual implementation of the algorithms,
//       but all invariants, data shapes and expectations are specified here.

#ifndef GOMOKU_THREAT_SOLVER_H
#define GOMOKU_THREAT_SOLVER_H

#include <array>
#include <bitset>
#include <cstdint>
#include <limits>
#include <optional>
#include <vector>

#include "board.h"

namespace gomoku {

//------------------------------------------------------------------------------
// Tunable constants for this engine
//------------------------------------------------------------------------------

constexpr int GOMOKU_BOARD_SIZE   = 12;
constexpr int GOMOKU_WIN_LENGTH   = 5;
constexpr int GOMOKU_MAX_LINE_LEN = GOMOKU_BOARD_SIZE; // 12 for 12×12

// Four 1D directions in which lines exist.
enum class Direction : uint8_t {
    Horizontal = 0,
    Vertical   = 1,
    DiagNWSE   = 2, // ↘
    DiagNESW   = 3  // ↙
};

//------------------------------------------------------------------------------
// Threat taxonomy
//------------------------------------------------------------------------------
//
// We follow Tomek Czajka’s categorization of threats, parameterized by (a, b):
//   - a = number of our stones towards a five (severity 1..5)
//   - b = number of distinct ways this pattern can be completed to a five.  [oai_citation:3‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
// Threat types:
//
//   Winning threats:
//     (5, 1): Five
//     (4, 2): Open four
//
//   Forcing threats (opponent must answer *somewhere* or lose):
//     (4, 1): Simple four
//     (3, 3): Open three
//     (3, 2): Broken three
//
//   Non-forcing threats (used in evaluation, not in the forcing sequence search)
//     (3, 1): Simple three
//     (2, k), (1, k): “twos” and “ones” with various multiplicities
//
// For threat sequence search we mainly care about:
//   - Five, OpenFour, SimpleFour, OpenThree, BrokenThree
// but we keep a richer enum so we can reuse the pattern tables in evaluation.

enum class ThreatType : uint8_t {
    None = 0,      // no threat in this direction

    // Winning
    Five,          // (5,1) – immediate win
    OpenFour,      // (4,2) – two different winning continuations, no defense

    // Forcing
    SimpleFour,    // (4,1) – one winning continuation, defense is unique
    OpenThree,     // (3,3) – 3 continuations, 2 defense points, 4 empties
    BrokenThree,   // (3,2) – 2 defense points, 3 empties

    // Non-forcing (for completeness, mostly used in static eval)
    SimpleThree,   // (3,1)
    TwoFourWays,   // (2,4)
    TwoThreeWays,  // (2,3)
    TwoTwoWays,    // (2,2)
    TwoOneWay,     // (2,1)
    OneFiveWays,   // (1,5)
    OneFourWays,   // (1,4)
    OneThreeWays,  // (1,3)
    OneTwoWays,    // (1,2)
    OneOneWay      // (1,1)
};

// Severity = how close to five (a in (a,b))
inline int threatSeverity(ThreatType t) noexcept {
    switch (t) {
        case ThreatType::Five:         return 5;
        case ThreatType::OpenFour:
        case ThreatType::SimpleFour:   return 4;
        case ThreatType::OpenThree:
        case ThreatType::BrokenThree:
        case ThreatType::SimpleThree:  return 3;
        case ThreatType::TwoFourWays:
        case ThreatType::TwoThreeWays:
        case ThreatType::TwoTwoWays:
        case ThreatType::TwoOneWay:    return 2;
        case ThreatType::OneFiveWays:
        case ThreatType::OneFourWays:
        case ThreatType::OneThreeWays:
        case ThreatType::OneTwoWays:
        case ThreatType::OneOneWay:    return 1;
        default:                       return 0;
    }
}

// Multiplicity = number of distinct ways to complete a five (b in (a,b))
inline int threatMultiplicity(ThreatType t) noexcept {
    switch (t) {
        case ThreatType::Five:           return 1; // already five
        case ThreatType::OpenFour:       return 2;
        case ThreatType::SimpleFour:     return 1;
        case ThreatType::OpenThree:      return 3;
        case ThreatType::BrokenThree:    return 2;
        case ThreatType::SimpleThree:    return 1;
        case ThreatType::TwoFourWays:    return 4;
        case ThreatType::TwoThreeWays:   return 3;
        case ThreatType::TwoTwoWays:     return 2;
        case ThreatType::TwoOneWay:      return 1;
        case ThreatType::OneFiveWays:    return 5;
        case ThreatType::OneFourWays:    return 4;
        case ThreatType::OneThreeWays:   return 3;
        case ThreatType::OneTwoWays:     return 2;
        case ThreatType::OneOneWay:      return 1;
        default:                         return 0;
    }
}

//------------------------------------------------------------------------------
// Threat pattern representation (1D)
//------------------------------------------------------------------------------
//
// Threat patterns are defined in *1D* along a single line (row / column / diag).
//
// For each pattern we store three disjoint bitmasks over a small window of
// cells (up to 12 bits, since the board is 12×12). The window is always a
// contiguous sub-line (no opponent stones inside).
//
//   - stonesMask:    cells that must be occupied by the attacker’s stones.
//   - emptyMask:     cells that must be empty for the pattern to be valid
//                    (includes defense spots and auxiliary empties).
//   - defenseMask:   subset of emptyMask where the defender is *allowed* to
//                    place a stone in response to this threat.
//
// For some patterns (e.g. open three) emptyMask contains 4 cells, but only 2
// are in defenseMask (the two true defense points). The other 2 are “auxiliary
// empties” that must remain empty but cannot be used as defenses.  [oai_citation:4‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
// From these masks we derive, per *instance* of a pattern on the board:
//
//   - Attack finishing moves (where the attacker will later play to complete
//     an open four or five).
//   - Squares that must remain empty due to open-three ordering constraints.
//   - Threat dependencies along the line (which threats depend on which other
//     threats having been played first).
//
// The static pattern table is shared by all ThreatSolver instances.

struct ThreatPattern {
    // “Shape” of the threat in 1D (direction-agnostic).
    ThreatType type = ThreatType::None;

    // Number of cells in the 1D window (5..12).
    uint8_t windowLen = 0;

    // Bit i (0 <= i < windowLen) refers to offset i in the window.
    // All masks are disjoint subsets of bits 0..windowLen-1.
    uint16_t stonesMask   = 0; // must be attacker stones
    uint16_t emptyMask    = 0; // must be empty (includes defenses)
    uint16_t defenseMask  = 0; // subset of emptyMask: legal defense points

    // For some algorithms it is convenient to have these precomputed:
    uint16_t finishingMask = 0; // subset of emptyMask: direct win squares
                                // (for fives this is empty; for open fours:
                                // two bits; for some open threes: set of
                                // squares that will form the future open four)

    // (a,b) parameters for this pattern.
    uint8_t a = 0; // severity (stones towards five)
    uint8_t b = 0; // multiplicity (finishing ways)

    // Identifier of this pattern in the global table, used as a compact key.
    uint8_t patternId = 0;
};

//------------------------------------------------------------------------------
// Threat instance (2D)
//
// A threat pattern instantiated at specific coordinates and direction.
//------------------------------------------------------------------------------

struct ThreatInstance {
    ThreatType type = ThreatType::None;

    // Attacking player that owns this threat.
    Player owner = Player::Black;

    // Direction along which the pattern lies.
    Direction dir = Direction::Horizontal;

    // 2D board coordinates of all relevant squares (small fixed arrays for
    // cache-friendliness; counts indicate how many are actually used).
    //
    // NOTE: We store *absolute* coordinates instead of relative offsets so that
    //       higher-level code (search engine, history heuristic) can reason
    //       about concrete moves without needing to know about directions.

    // Squares that must currently be occupied by the attacker.
    std::array<Move, GOMOKU_WIN_LENGTH> stones{};
    uint8_t stonesCount = 0;

    // Empty squares that must remain empty for this threat to be valid.
    std::array<Move, 4> requiredEmpty{};
    uint8_t requiredEmptyCount = 0;

    // Squares where the defender may respond to this threat (defenseMask).
    std::array<Move, 4> defenses{};
    uint8_t defenseCount = 0;

    // Squares where the attacker will later move to convert the threat into a
    // higher-level threat / immediate win (open three ⇒ open four, four ⇒ five).
    std::array<Move, 3> finishing{};
    uint8_t finishingCount = 0;

    // Optional: index into the static pattern table for reconstruction.
    uint8_t patternId = 0;
};

//------------------------------------------------------------------------------
// Threat sequence & defensive set
//------------------------------------------------------------------------------
//
// Threat sequence search is the “solver” part. For the attacker we want to:
//
//   - Find a *sequence* of threats (nodes in a DAG) such that:
//       * At each step, the defender is forced to answer (or else loses).
//       * After all threats are played, we reach a winning threat
//         (Five or OpenFour).
//       * The sequence respects all ordering dependencies (open-three
//         auxiliary empties, no overlapping threats, etc.).  [oai_citation:5‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
//   - Exploit Allis’ "all-defenses" trick: for each threat, assume the defender
//     plays *all* its defenses at once, turning the search into a single-player
//     game on a board that accumulates both attacker and defender stones.  [oai_citation:6‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
//
// For the defender, we want:
//
//   - The *set of moves* that defend against *all* winning sequences found for
//     the attacker (or detect that this set is empty, meaning the node is lost).
//   - This set is used by the Search Engine to aggressively prune moves that do
//     not defend against any discovered winning sequence, dramatically reducing
//     branching factor in tactical positions.  [oai_citation:7‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)

struct ThreatSequence {
    // The threats in logical order (respecting dependencies).
    std::vector<ThreatInstance> threats;

    // Concrete move sequence for both players under “all-defenses”.
    //
    // For each ThreatInstance T:
    //   - attackerMove[k] = stone that creates T
    //   - defenderMoves may contain 0..3 stones that defend against T,
    //     all assumed to be played simultaneously (Allis trick).
    //
    // This makes ThreatSequence directly replayable on a Board copy if needed.
    std::vector<Move> attackerMoves;
    std::vector<Move> defenderMoves;
};

// When we discover that the opponent has at least one winning sequence, we
// additionally want the set of *valid defenses* – moves for the current player
// that neutralize *all* those sequences. This result is obtained via the
// “defenses to potential threat sequences” algorithm in the reference.  [oai_citation:8‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
struct DefensiveSet {
    bool isLost = false; // true ⇒ no defensive move exists, node is terminal

    // If !isLost, these are the moves that keep the position alive. The search
    // engine should only expand these moves in this node.
    std::vector<Move> defensiveMoves;
};

//------------------------------------------------------------------------------
// Search limits / configuration
//------------------------------------------------------------------------------

struct ThreatSearchLimits {
    // Hard cap on total nodes (threat nodes + combination nodes) in the
    // dependency-based search graph for a single call.
    int maxNodes = 200000;

    // Maximum logical depth (number of threat layers). Enough for practical
    // games; typical winning sequences are < 20 threats on a 12×12 board.
    int maxDepth = 20;

    // Optional external abort flag (owned by Search Engine).
    // If non-null and *abortFlag becomes true during search, ThreatSolver will
    // terminate early and report “no sequence found / no information”.
    const bool* abortFlag = nullptr;
};

//------------------------------------------------------------------------------
// ThreatSolver – public interface
//------------------------------------------------------------------------------

class ThreatSolver {
public:
    //------------------------------------------------------------------------
    // Construction / synchronization
    //------------------------------------------------------------------------

    // Construct a ThreatSolver initialized from the given board.
    //
    //   - Iterates over all 144 cells, builds internal rotated bitboards for
    //     both players and all 4 directions.
    //   - Builds full threat boards for both players by scanning only the
    //     sub-lines that contain stones (using the precomputed pattern tables).
    //
    // This cost is paid only at the root; the Search Engine should prefer to
    // reuse the same ThreatSolver instance and use syncFromBoard() only when
    // the root board changes (e.g., at the beginning of a new move).
    explicit ThreatSolver(const Board& board);

    // Force a full re-sync of internal data structures with the given board.
    //
    // Intended for:
    //   - New root positions (e.g. after opponent move is received).
    //   - Unit tests where Board is manipulated directly.
    //
    // Not performance-critical; avoids subtle bugs where ThreatSolver and Board
    // drift out of sync.
    void syncFromBoard(const Board& board);

    //------------------------------------------------------------------------
    // Incremental notifications (optional but recommended)
    //------------------------------------------------------------------------
    //
    // Search Engine integration model:
    //
    //   - The main search tree uses Board::makeMove / Board::unmakeMove.
    //   - After *each* such call at the root, it *may* notify ThreatSolver
    //     via onRootMoveMade/onRootMoveUndone so internal rotated bitboards and
    //     threat boards remain in sync.
    //
    // Note: Threat sequence search itself operates on *copies* of these bitboards
    // and never modifies the user's Board. Notifications are only needed for
    // *root* changes, not for internal hypothetical moves in the threat search.

    // Call immediately *after* Board::makeMove(x,y) at root.
    void onRootMoveMade(const Move& m);

    // Call immediately *after* Board::unmakeMove(x,y) at root.
    void onRootMoveUndone(const Move& m);

    //------------------------------------------------------------------------
    // Main query: does ATTACKER have a winning threat sequence?
    //------------------------------------------------------------------------
    //
    // Returns:
    //   - true  if we found at least one forcing winning sequence for attacker.
    //   - false if we could not find a sequence within limits.
    //
    // On success:
    //   - outSequence contains *one* (not necessarily unique) winning sequence.
    //
    // On failure:
    //   - outSequence is left unchanged (or cleared; up to implementation).
    //
    // Important:
    //   - “false” does *not* guarantee that no winning sequence exists; it may
    //     also mean the search was aborted due to limits / abortFlag.
    //   - The Search Engine can distinguish “no info” vs “proven no sequence”
    //     by choosing sufficiently generous limits relative to the position.
    bool findWinningThreatSequence(Player attacker,
                                   ThreatSequence& outSequence,
                                   const ThreatSearchLimits& limits = {}) const;

    //------------------------------------------------------------------------
    // Main query: defensive move set for DEFENDER (opponent’s threats)
    //------------------------------------------------------------------------
    //
    // Conceptually:
    //   1. Assume *opponent* is the attacker and run dependency-based search
    //      for his winning sequences.
    //   2. If none found, we return DefensiveSet{ isLost = false,
    //                                             defensiveMoves = allLegal }
    //      and the Search Engine can proceed normally.
    //   3. If at least one winning sequence is found, we compute the *set of
    //      moves that defend against all such sequences*, following
    //      "Defenses to potential threat sequences" from the reference.  [oai_citation:9‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
    //   4. If this set is empty, the node is lost and the search can terminate.
    //
    // Usage pattern in the main Search Engine:
    //
    //   DefensiveSet ds = solver.computeDefensiveSet(board.sideToMove(), limits);
    //   if (ds.isLost) {
    //       // score node as immediate loss for sideToMove()
    //   } else if (!ds.defensiveMoves.empty()) {
    //       // Only expand ds.defensiveMoves as legal children from this node
    //   } else {
    //       // No immediate threats; expand usual move list
    //   }
    //
    DefensiveSet computeDefensiveSet(Player defender,
                                     const ThreatSearchLimits& limits = {}) const;

    //------------------------------------------------------------------------
    // Lightweight queries used for move ordering / heuristics
    //------------------------------------------------------------------------

    // Check whether the given player *currently* has any winning threat
    // (Five or OpenFour) already present on the board.
    //
    // This is much cheaper than a full threat sequence search, as it uses only
    // the threat board around the last move.
    bool hasImmediateWinningThreat(Player player) const;

    // Return all *forcing* threats (SimpleFour, OpenThree, BrokenThree) that
    // are currently available for the given player, as seen from the threat
    // board populated from the *current* Board state.
    //
    // This is useful for:
    //   - Move ordering (try moves that immediately create forcing threats).
    //   - Breadth-limited tactical searches.
    void collectCurrentForcingThreats(Player player,
                                      std::vector<ThreatInstance>& out) const;

private:
    //==========================================================================
    // Internal data structures
    //==========================================================================

    //--------------------------------------------------------------------------
    // Rotated bitboards
    //--------------------------------------------------------------------------
    //
    // We store one bitboard per (player, direction) pair, each covering all 12×12
    // intersections. The mapping is chosen such that intersections in a single
    // line in that direction map to *consecutive* bits.  [oai_citation:10‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
    //
    //   dir = Horizontal: rows become contiguous
    //   dir = Vertical:   columns become contiguous
    //   dir = DiagNWSE:   NW–SE diagonals become contiguous
    //   dir = DiagNESW:   NE–SW diagonals become contiguous
    //
    // With this representation, extracting any line reduces to:
    //
    //   - Compute base index of the line and its length.
    //   - Extract a contiguous slice of bits using shifts & masks.
    //
    // We do not impose any particular packing (16×16 vs 12×12) here; the
    // implementation is free to pick whatever is convenient as long as it
    // exposes the following guarantees:
    //
    //   - Each valid (x,y) ∈ [0,11]² maps to a unique bit index per direction.
    //   - For any fixed direction and fixed line, bit indices are contiguous.
    //
    // We keep them as simple arrays of 64-bit chunks for cache-friendliness.

    struct RotatedBitboards {
        // bb[playerIndex][dirIndex][chunk]
        //   playerIndex: 0 = Black, 1 = White
        //   dirIndex:    0..3 (Direction cast to uint8_t)
        //   chunk:       0..2 (3×64 = 192 bits → enough for 144 cells)
        uint64_t bb[2][4][3] = {};

        // Set / clear a bit for (player, x, y) in all 4 directions.
        void setStone(Player p, int x, int y);
        void clearStone(Player p, int x, int y);

        // Extract a raw bitmask for a given line. Implementation is responsible
        // for:
        //   - Mapping (dir, lineId) to (chunkBase, bitOffset, length)
        //   - Returning a uint16_t/uint32_t with the least significant 'len'
        //     bits representing the line contents (1 = stone present).
        //
        // Note: “lineId” is an internal index (0..NdirLines-1) per direction.
        uint32_t extractLine(Player p, Direction dir,
                             int lineId, int& outLen) const;
    };

    //--------------------------------------------------------------------------
    // ThreatBoard – local threats at each cell
    //--------------------------------------------------------------------------
    //
    // For static evaluation and seed nodes in dependency-based search we want
    // to know, for each empty intersection and each direction, what the *best*
    // available threat is at that intersection for a given player.  [oai_citation:11‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
    //
    // ThreatBoard stores this “micro” view of threats.

    struct ThreatCell {
        // Best threat type in this direction when the owner plays here.
        ThreatType type = ThreatType::None;

        // Optional: index into pattern table, etc., for reconstruction.
        uint8_t patternId = 0;
    };

    struct ThreatBoard {
        // threats[player][y][x][dir]
        ThreatCell cells[2][GOMOKU_BOARD_SIZE][GOMOKU_BOARD_SIZE][4]{};

        // Clear all entries.
        void clear();

        // Recompute threat info for all cells from scratch, using current
        // rotated bitboards and pattern tables.
        void rebuild(const RotatedBitboards& rbb);

        // Incremental update around a newly placed or removed stone at (x,y)
        // for both players.
        //
        // As described in the reference, we only need to walk up to distance 4
        // in each direction (enough to cover any 5-in-a-row window that touches
        // (x,y)), so we update at most 8*4 = 32 intersections.  [oai_citation:12‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
        //
        // Implementation will:
        //   - For each affected empty cell c within radius 4 of (x,y):
        //       * For each direction d:
        //           - Extract the 1D sub-line that contains c and has no
        //             opponent stones (using rotated bitboards).
        //           - Use the attacker's stone pattern in that sub-line as an
        //             index into the precomputed lookup table to get the best
        //             ThreatPattern for that (player,c,d).
        //           - Store the resulting ThreatCell.
        void incrementalUpdate(const RotatedBitboards& rbb, int x, int y);
    };

    //--------------------------------------------------------------------------
    // Static pattern tables
    //--------------------------------------------------------------------------
    //
    // We use precomputed lookup tables for fast pattern recognition:  [oai_citation:13‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
    //
    //   1. For each line length L ∈ [5,12] and each pattern of *opponent* stones
    //      on that line, we precompute how the line is split into sub-lines by
    //      opponent stones. Any threat must be contained entirely inside a
    //      sub-line without opponent stones.
    //
    //   2. For each sub-line length S ∈ [5,12] and each pattern of *our* stones
    //      (bitmask in [0, 2^S)), we precompute:
    //        - All ThreatPatterns that exist within that sub-line (possibly
    //          multiple per sub-line, anchored at different empty cells).
    //        - The “best” ThreatPattern for each empty cell, for quick lookup
    //          in ThreatBoard::incrementalUpdate.
    //
    // PatternTable encapsulates this precomputation and provides:
    //   - The master list of ThreatPattern definitions.
    //   - A fast lookup “stonesMask → list of patterns” for threat search.
    //   - A fast lookup “(S, stonesMask, cellOffset) → best ThreatPatternId”
    //     for ThreatBoard updates.

    struct PatternTable {
        // Master list of all distinct threat shapes (≈65 as in the reference,
        // but for a 12×12 board lines this number can be slightly smaller).
        std::vector<ThreatPattern> patterns;

        // For each sub-line length S ∈ [5,12], and each possible stonesMask in
        // [0, 2^S), we store:
        //
        //   candidatePatternIds[S][stonesMask] = vector of patternIds that
        //   can occur in this sub-line given this distribution of our stones.
        //
        // Implementation detail:
        //   - Index by S-5 so we use 0..7 instead of 5..12 for outer index.
        //   - Use a flat vector<vector<>> or a two-dimensional array.
        std::vector<std::vector<std::vector<uint8_t>>> candidatePatternIds;

        // For ThreatBoard: for each (S, stonesMask, cellOffset) we want the
        // *best* threat type available when playing on that empty cell. So we
        // precompute:
        //
        //   bestPatternAtCell[S][stonesMask][cellOffset] = patternId (or 0xFF
        //   if no threat).
        //
        // “Best” can be ordered by:
        //   1. severity (a),
        //   2. multiplicity (b),
        //   3. patternId as tie-breaker for deterministic behavior.
        std::vector<std::vector<std::array<uint8_t, GOMOKU_MAX_LINE_LEN>>> bestPatternAtCell;

        // Initialize all tables. This is invoked lazily the first time any
        // ThreatSolver is constructed.
        void initializeOnce();

        // Singleton accessor. Implementation may guard with std::once_flag.
        static const PatternTable& instance();
    };

    //--------------------------------------------------------------------------
    // Threat search graph (internal)
    //--------------------------------------------------------------------------
    //
    // We do not expose the full dependency graph outside ThreatSolver, but
    // conceptually it consists of two node types:  [oai_citation:14‡Sorting and Searching](https://sortingsearching.com/2020/05/18/gomoku.html)
    //
    //   - ThreatNode: A single threat (SimpleFour, OpenThree, BrokenThree,
    //     OpenFour, Five), referencing the board squares it uses.
    //
    //   - CombinationNode: A combination of two (or more) threats on the same
    //     line (e.g. two broken threes) that together enable another threat.
    //
    // Edges represent “enables” dependencies: A → B if executing threat A
    // enables threat B (by adding stones). We maintain a DAG and perform a
    // topological exploration, pruning combinations that:
    //
    //   - Overlap on any square in incompatible ways (e.g. both want to place
    //     stones on the same cell in conflicting roles).
    //   - Violate open-three “auxiliary empty” ordering constraints (squares
    //     that must remain empty until the open-three is executed).
    //
    // For brevity we only sketch key structs here; the full details live in the
    // .cpp implementation.

    struct ThreatNode {
        ThreatInstance instance;              // concrete threat
        std::vector<int> prerequisites;      // indices of nodes that must be executed first
        bool isWinning = false;              // OpenFour or Five
    };

    struct CombinationNode {
        // Indices of ThreatNode/CombinationNode that are combined here.
        std::vector<int> components;

        // Aggregate instance: union of all stones/requiredEmpty/defenses/etc.
        ThreatInstance combinedInstance;

        // Transitive prerequisites (union of all components’ prerequisites).
        std::vector<int> prerequisites;

        bool isWinning = false;
    };

    // Internal search context for a single call to findWinningThreatSequence /
    // computeDefensiveSet. It owns:
    //
    //   - A local copy of rotated bitboards + ThreatBoard for both players,
    //     modified during the single-player threat search under Allis’ trick.
    //   - The DAG of ThreatNode / CombinationNode.
    //   - Counters for nodes, depth, and quick-abort based on ThreatSearchLimits.
    struct SearchContext;

    //==========================================================================
    // Member data
    //==========================================================================

    RotatedBitboards rotated_;
    ThreatBoard      threats_;

    // We only need a pointer to the current root Board for sanity checks and
    // to know which side is to move, but we never mutate it.
    const Board* rootBoard_ = nullptr;

    //==========================================================================
    // Internal helpers (implemented in .cpp)
    //==========================================================================

    // Rebuild rotated_ from a full Board scan.
    void rebuildRotatedBitboards(const Board& board);

    // Initialize threats_ from rotated_.
    void rebuildThreatBoard();

    // All heavy lifting is delegated to SearchContext; these wrappers just
    // construct the context and translate results to public structs.

    bool runWinningThreatSearch(Player attacker,
                                ThreatSequence& outSeq,
                                const ThreatSearchLimits& limits) const;

    DefensiveSet runDefensiveSetSearch(Player defender,
                                       const ThreatSearchLimits& limits) const;
};

} // namespace gomoku

#endif // GOMOKU_THREAT_SOLVER_H