// threat_solver.cpp
//
// Simplified, fully-compilable implementation of ThreatSolver.
//
// NOTE: This is a *minimal functional* implementation:
//   - It keeps ThreatSolver in sync with Board.
//   - It detects immediate winning moves (one move to make five).
//   - computeDefensiveSet handles immediate one-move wins and double threats.
//   - ThreatBoard and PatternTable are implemented as stubs (no advanced
//     pattern recognition yet).
//
// This is a good starting point that can be extended later with the full
// Victor Allis style dependency-based threat search.
//

#include "threat_solver.h"

#include <algorithm>
#include <cstring>
#include <mutex>

namespace gomoku {

//------------------------------------------------------------------------------
// Small helpers
//------------------------------------------------------------------------------

static inline int boardIndex(int x, int y) {
    return y * GOMOKU_BOARD_SIZE + x;
}

static inline int playerIndex(Player p) {
    return (p == Player::Black) ? 0 : 1;
}

static inline Player otherPlayer(Player p) {
    return (p == Player::Black) ? Player::White : Player::Black;
}

// Check coordinates are on board
static inline bool onBoard(int x, int y) {
    return x >= 0 && x < GOMOKU_BOARD_SIZE && y >= 0 && y < GOMOKU_BOARD_SIZE;
}

//------------------------------------------------------------------------------
// ThreatSolver::RotatedBitboards
//------------------------------------------------------------------------------
// Current simplified implementation:
//   - We only store a basic bitboard per player in direction index 0.
//   - Other directions and extractLine() are essentially unused stubs.
//   - All higher-level logic reads directly from Board, so this is just to
//     satisfy the interface and keep future extensibility.
//

void ThreatSolver::RotatedBitboards::setStone(Player p, int x, int y) {
    int pIdx = playerIndex(p);
    int idx  = boardIndex(x, y);
    int chunk = idx >> 6;
    int offset = idx & 63;
    bb[pIdx][0][chunk] |= (uint64_t(1) << offset);
}

void ThreatSolver::RotatedBitboards::clearStone(Player p, int x, int y) {
    int pIdx = playerIndex(p);
    int idx  = boardIndex(x, y);
    int chunk = idx >> 6;
    int offset = idx & 63;
    bb[pIdx][0][chunk] &= ~(uint64_t(1) << offset);
}

uint32_t ThreatSolver::RotatedBitboards::extractLine(Player p,
                                                     Direction /*dir*/,
                                                     int /*lineId*/,
                                                     int& outLen) const {
    // Minimal stub: we don't currently use this in the simplified solver.
    outLen = 0;
    (void)p;
    return 0;
}

//------------------------------------------------------------------------------
// ThreatSolver::ThreatBoard
//------------------------------------------------------------------------------

void ThreatSolver::ThreatBoard::clear() {
    std::memset(cells, 0, sizeof(cells));
}

void ThreatSolver::ThreatBoard::rebuild(const RotatedBitboards& /*rbb*/) {
    // Minimal implementation: clear and leave all threats as None.
    clear();
}

void ThreatSolver::ThreatBoard::incrementalUpdate(const RotatedBitboards& rbb,
                                                  int /*x*/, int /*y*/) {
    // For now, just rebuild everything (still cheap on 12×12) or no-op.
    // To keep it simple and correct, we call rebuild.
    rebuild(rbb);
}

//------------------------------------------------------------------------------
// ThreatSolver::PatternTable
//------------------------------------------------------------------------------

void ThreatSolver::PatternTable::initializeOnce() {
    if (!patterns.empty()) return; // already initialized

    // Minimal stub: no actual patterns yet.
    patterns.clear();
    candidatePatternIds.clear();
    bestPatternAtCell.clear();
}

const ThreatSolver::PatternTable& ThreatSolver::PatternTable::instance() {
    static PatternTable table;
    static std::once_flag once;
    std::call_once(once, [&]() {
        table.initializeOnce();
    });
    return table;
}

//------------------------------------------------------------------------------
// ThreatSolver::SearchContext
//------------------------------------------------------------------------------

struct ThreatSolver::SearchContext {
    Board boardCopy;
    Player attacker;
    ThreatSearchLimits limits;
    int nodes = 0;

    SearchContext(const Board& root, Player a, const ThreatSearchLimits& lim)
        : boardCopy(root), attacker(a), limits(lim) {}
};

//------------------------------------------------------------------------------
// ThreatSolver: construction / sync
//------------------------------------------------------------------------------

ThreatSolver::ThreatSolver(const Board& board) {
    PatternTable::instance(); // ensure pattern tables constructed (even if stub)
    syncFromBoard(board);
}

void ThreatSolver::syncFromBoard(const Board& board) {
    rootBoard_ = &board;
    rebuildRotatedBitboards(board);
    rebuildThreatBoard();
}

void ThreatSolver::onRootMoveMade(const Move& m) {
    if (!rootBoard_) return;

    // After Board::makeMove, sideToMove() is the *next* player.
    // The stone that was just placed belongs to the opposite side.
    Player last = otherPlayer(rootBoard_->sideToMove());
    rotated_.setStone(last, m.x, m.y);
    threats_.incrementalUpdate(rotated_, m.x, m.y);
}

void ThreatSolver::onRootMoveUndone(const Move& m) {
    if (!rootBoard_) return;

    // After Board::unmakeMove, sideToMove() is the player whose stone was
    // just removed. So we clear that stone for sideToMove().
    Player p = rootBoard_->sideToMove();
    rotated_.clearStone(p, m.x, m.y);
    threats_.incrementalUpdate(rotated_, m.x, m.y);
}

//------------------------------------------------------------------------------
// Internal: rebuild from Board
//------------------------------------------------------------------------------

void ThreatSolver::rebuildRotatedBitboards(const Board& board) {
    std::memset(rotated_.bb, 0, sizeof(rotated_.bb));

    for (int y = 0; y < GOMOKU_BOARD_SIZE; ++y) {
        for (int x = 0; x < GOMOKU_BOARD_SIZE; ++x) {
            int state = board.getCellState(x, y);
            if (state == 1) {
                rotated_.setStone(Player::Black, x, y);
            } else if (state == 2) {
                rotated_.setStone(Player::White, x, y);
            }
        }
    }
}

void ThreatSolver::rebuildThreatBoard() {
    threats_.rebuild(rotated_);
}

//------------------------------------------------------------------------------
// Minimal immediate winning move detection
//------------------------------------------------------------------------------

static bool isImmediateWinningMove(Board& board,
                                   const Move& m,
                                   Player attacker) {
    // Assumes m is empty on board.
    if (!board.makeMove(m.x, m.y)) {
        return false;
    }
    bool win = board.checkWin(attacker);
    board.unmakeMove(m.x, m.y);
    return win;
}

//------------------------------------------------------------------------------
// ThreatSolver: public queries
//------------------------------------------------------------------------------

bool ThreatSolver::findWinningThreatSequence(Player attacker,
                                             ThreatSequence& outSequence,
                                             const ThreatSearchLimits& limits) const {
    return runWinningThreatSearch(attacker, outSequence, limits);
}

DefensiveSet ThreatSolver::computeDefensiveSet(Player defender,
                                               const ThreatSearchLimits& limits) const {
    return runDefensiveSetSearch(defender, limits);
}

bool ThreatSolver::hasImmediateWinningThreat(Player player) const {
    if (!rootBoard_) return false;

    // 1) Already-winning position (five on board).
    if (rootBoard_->checkWin(player)) {
        return true;
    }

    // 2) Any immediate winning move?
    Board tmp = *rootBoard_;
    auto legal = tmp.getLegalMoves();
    for (const auto& m : legal) {
        if (isImmediateWinningMove(tmp, m, player)) {
            return true;
        }
    }
    return false;
}

void ThreatSolver::collectCurrentForcingThreats(Player player,
                                                std::vector<ThreatInstance>& out) const {
    if (!rootBoard_) return;

    Board tmp = *rootBoard_;
    auto legal = tmp.getLegalMoves();
    for (const auto& m : legal) {
        if (isImmediateWinningMove(tmp, m, player)) {
            ThreatInstance t;
            t.type  = ThreatType::Five;
            t.owner = player;
            t.stonesCount = 0;
            t.requiredEmptyCount = 0;
            t.defenseCount = 0;
            t.finishingCount = 1;
            t.finishing[0] = m;
            out.push_back(t);
        }
    }
}

//------------------------------------------------------------------------------
// Internal: simplified winning threat search
//------------------------------------------------------------------------------
//
// We implement a minimal "one-ply" threat search:
//
//   - If attacker already has five in a row: treat as winning.
//   - Else, if attacker has a move that makes a five: treat that as a winning
//     sequence of length 1.
//
// This is intentionally simple but correct for immediate tactical wins.
// It can be replaced later with a full dependency-based threat sequence search.
//

bool ThreatSolver::runWinningThreatSearch(Player attacker,
                                          ThreatSequence& outSeq,
                                          const ThreatSearchLimits& limits) const {
    if (!rootBoard_) return false;

    SearchContext ctx(*rootBoard_, attacker, limits);

    // 1) Already winning position.
    if (ctx.boardCopy.checkWin(attacker)) {
        ThreatSequence seq;
        // We don't attempt to reconstruct the exact five; at the engine level,
        // knowing "there is a winning threat right now" is enough.
        outSeq = std::move(seq);
        return true;
    }

    // 2) Any immediate winning move?
    auto legal = ctx.boardCopy.getLegalMoves();
    for (const auto& m : legal) {
        if (ctx.limits.abortFlag && *ctx.limits.abortFlag) {
            return false; // aborted, no information
        }
        if (++ctx.nodes > ctx.limits.maxNodes) {
            return false; // hit node limit, no information
        }

        if (isImmediateWinningMove(ctx.boardCopy, m, attacker)) {
            ThreatSequence seq;
            ThreatInstance t;
            t.type  = ThreatType::Five;
            t.owner = attacker;
            t.finishing[0] = m;
            t.finishingCount = 1;
            seq.threats.push_back(t);
            seq.attackerMoves.push_back(m);
            outSeq = std::move(seq);
            return true;
        }
    }

    return false;
}

//------------------------------------------------------------------------------
// Internal: simplified defensive set search
//------------------------------------------------------------------------------
//
// We look only for *immediate* winning moves from the opponent:
//
//   - attacker = otherPlayer(defender)
//   - Find all moves where attacker can immediately make a five.
//   - If none:   isLost = false, defensiveMoves = {} (search engine plays all).
//   - If one:    isLost = false, defensiveMoves = { that move }.
//   - If >1:     isLost = true (double threat).
//

DefensiveSet ThreatSolver::runDefensiveSetSearch(Player defender,
                                                 const ThreatSearchLimits& limits) const {
    DefensiveSet result;
    if (!rootBoard_) return result;

    Player attacker = otherPlayer(defender);

    Board tmp = *rootBoard_;
    auto legal = tmp.getLegalMoves();

    std::vector<Move> winningMoves;
    int nodes = 0;

    for (const auto& m : legal) {
        if (limits.abortFlag && *limits.abortFlag) {
            // Abort → return "no information", i.e., not lost, no restricted set.
            return result;
        }
        if (++nodes > limits.maxNodes) {
            // Hit node cap → same: no information.
            return result;
        }

        if (isImmediateWinningMove(tmp, m, attacker)) {
            winningMoves.push_back(m);
        }
    }

    if (winningMoves.empty()) {
        // No immediate wins for opponent.
        result.isLost = false;
        // defensiveMoves left empty ⇒ search engine can expand all legal moves.
        return result;
    }

    if (winningMoves.size() == 1) {
        // Single winning move: defender must block it.
        result.isLost = false;
        result.defensiveMoves.push_back(winningMoves.front());
        return result;
    }

    // Multiple distinct immediate wins → position is lost.
    result.isLost = true;
    return result;
}

} // namespace gomoku