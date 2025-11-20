#include "search.h"
#include <algorithm>
#include <chrono>
#include <limits>
#include <unordered_map>
#include <utility>

// Include history heuristic for move ordering.
#include "history_heuristic.h"
#include "threat_solver.h"

namespace gomoku {

SearchEngine::SearchEngine() : maxDepthReached(0) {
}

// Determine whether an opening move should be played for the current position.
// This simple opening book looks for the very first move (after the
// predetermined starting stones) and chooses a central point that expands
// the initial cross.  For Black, it recommends playing on the diagonal at
// (7,7).  For White or later positions, no opening move is returned.
bool SearchEngine::getOpeningMove(const Board &board, Player myColor, Move &outMove) const {
    // Count total stones on the board.
    int total = board.countStones(Player::Black) + board.countStones(Player::White);
    // The predetermined position has 4 stones.  We provide a book move
    // immediately after this position if it is our turn.  If total == 4
    // and it is Black’s turn, choose a point diagonally away from the
    // central cross.  For White or later positions, fall through.
    if (total == 4 && board.sideToMove() == myColor) {
        if (myColor == Player::Black) {
            const Move preferred[] = { Move(7,7), Move(7,4), Move(4,7), Move(4,4) };
            for (const auto &m : preferred) {
                if (!board.isOccupied(m.x, m.y)) {
                    outMove = m;
                    return true;
                }
            }
        }
    }
    // Second ply of opening: after Black’s book move, suggest a reply
    // for White.  When total stones == 5 (the predetermined four plus
    // Black’s first move) and it is White’s turn, choose a point
    // symmetrically opposite Black’s move.  This simple book aims to
    // maintain balance and spread stones evenly.  If the preferred
    // points are occupied, fall back to search.
    if (total == 5 && board.sideToMove() == myColor) {
        if (myColor == Player::White) {
            const Move preferred2[] = { Move(4,4), Move(4,7), Move(7,4), Move(7,7) };
            for (const auto &m : preferred2) {
                if (!board.isOccupied(m.x, m.y)) {
                    outMove = m;
                    return true;
                }
            }
        }
    }
    return false;
}

void SearchEngine::startTimer(int timeLimitMs) {
    timeEnd = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeLimitMs);
    maxDepthReached = 0;
}

bool SearchEngine::timeUp() const {
    return std::chrono::steady_clock::now() >= timeEnd;
}

int SearchEngine::patternScore(int count, bool leftOpen, bool rightOpen) const {
    // Assign scores for different pattern types.  Higher numbers correspond
    // to stronger tactical threats and are tuned heuristically.  A five
    // in a row (or longer) is a winning line and therefore receives the
    // largest score.  An “open four” (four contiguous stones with empty
    // squares on both sides) is nearly as strong because it can be extended
    // to five in one move from either end.  A “simple four” (four stones
    // with only one open end) is slightly weaker but still critical.  Open
    // threes (three stones with two open ends) are dangerous because they
    // force the opponent to defend immediately; we therefore assign them
    // a higher value than broken or closed threes.  Two‑stone patterns are
    // much less important and receive much smaller scores.  These values
    // can be adjusted to influence the playing style of the engine.
    const int SCORE_FIVE           = 100000000;
    const int SCORE_OPEN_FOUR      = 10000000;
    const int SCORE_SIMPLE_FOUR    = 1000000;
    const int SCORE_OPEN_THREE     = 500000;
    const int SCORE_BROKEN_THREE   = 100000;
    const int SCORE_OPEN_TWO       = 1000;
    const int SCORE_CLOSED_TWO     = 100;
    if (count >= 5) {
        return SCORE_FIVE;
    }
    if (count == 4) {
        if (leftOpen && rightOpen) return SCORE_OPEN_FOUR;
        if (leftOpen || rightOpen) return SCORE_SIMPLE_FOUR;
    }
    if (count == 3) {
        if (leftOpen && rightOpen) return SCORE_OPEN_THREE;
        // A three with only one open end is treated as a broken three.
        if (leftOpen || rightOpen) return SCORE_BROKEN_THREE;
    }
    if (count == 2) {
        if (leftOpen && rightOpen) return SCORE_OPEN_TWO;
        if (leftOpen || rightOpen) return SCORE_CLOSED_TWO;
    }
    return 0;
}

// Evaluate the board from a player's perspective by scanning rows,
// columns and both diagonals for contiguous runs of stones.  Only
// straight runs are considered; broken patterns (e.g., "xx.x") are
// not recognized explicitly but may still be partially credited.
int SearchEngine::evaluatePlayer(const Board &board, Player player) const {
    // Convert the board bitboards into a 2D integer array for easier
    // scanning.  We use the values 1 for the target player's stones,
    // -1 for the opponent's stones and 0 for empty.  This representation
    // allows us to recognise contiguous runs by simple loops.
    int grid[12][12];
    for (int y = 0; y < 12; ++y) {
        for (int x = 0; x < 12; ++x) {
            int state = board.getCellState(x, y);
            if (state == 0) {
                grid[y][x] = 0;
            } else if ((state == 1 && player == Player::Black) || (state == 2 && player == Player::White)) {
                // Current player's stone is represented by +1
                grid[y][x] = 1;
            } else {
                // Opponent's stone is represented by -1
                grid[y][x] = -1;
            }
        }
    }
    int score = 0;
    // --- Rows ---
    // Scan each row.  When we encounter a run of 1s, we measure its length
    // and check whether the ends are open (i.e. adjacent cells are empty).
    // The patternScore() function converts (count, leftOpen, rightOpen)
    // into a numerical threat value.
    for (int y = 0; y < 12; ++y) {
        int x = 0;
        while (x < 12) {
            if (grid[y][x] == 1) {
                int x1 = x;
                while (x < 12 && grid[y][x] == 1) ++x;
                int count = x - x1;
                bool leftOpen = (x1 - 1 >= 0 && grid[y][x1 - 1] == 0);
                bool rightOpen = (x < 12 && grid[y][x] == 0);
                score += patternScore(count, leftOpen, rightOpen);
            } else {
                ++x;
            }
        }
    }
    // --- Columns ---
    for (int x = 0; x < 12; ++x) {
        int y = 0;
        while (y < 12) {
            if (grid[y][x] == 1) {
                int y1 = y;
                while (y < 12 && grid[y][x] == 1) ++y;
                int count = y - y1;
                bool leftOpen = (y1 - 1 >= 0 && grid[y1 - 1][x] == 0);
                bool rightOpen = (y < 12 && grid[y][x] == 0);
                score += patternScore(count, leftOpen, rightOpen);
            } else {
                ++y;
            }
        }
    }
    // --- Diagonals (top‑left to bottom‑right) ---
    // For each diagonal index from -(rows-1) to (cols-1)
    for (int k = -11; k <= 11; ++k) {
        int xStart = std::max(0, k);
        int yStart = std::max(0, -k);
        int len = std::min(12 - xStart, 12 - yStart);
        int i = 0;
        while (i < len) {
            int xcur = xStart + i;
            int ycur = yStart + i;
            if (grid[ycur][xcur] == 1) {
                int j = i;
                while (j < len) {
                    int xj = xStart + j;
                    int yj = yStart + j;
                    if (grid[yj][xj] != 1) break;
                    ++j;
                }
                int count = j - i;
                bool leftOpen = false;
                if (i - 1 >= 0) {
                    int xl = xStart + (i - 1);
                    int yl = yStart + (i - 1);
                    if (grid[yl][xl] == 0) leftOpen = true;
                }
                bool rightOpen = false;
                if (j < len) {
                    int xr = xStart + j;
                    int yr = yStart + j;
                    if (grid[yr][xr] == 0) rightOpen = true;
                }
                score += patternScore(count, leftOpen, rightOpen);
                i = j;
            } else {
                ++i;
            }
        }
    }
    // --- Anti‑diagonals (top‑right to bottom‑left) ---
    // For each anti-diagonal index (x+y) from 0 to 22
    for (int s = 0; s <= 22; ++s) {
        int xStart = std::max(0, s - 11);
        int yStart = std::min(11, s);
        int len = std::min(yStart + 1, 12 - xStart);
        int i = 0;
        while (i < len) {
            int xcur = xStart + i;
            int ycur = yStart - i;
            if (grid[ycur][xcur] == 1) {
                int j = i;
                while (j < len) {
                    int xj = xStart + j;
                    int yj = yStart - j;
                    if (grid[yj][xj] != 1) break;
                    ++j;
                }
                int count = j - i;
                bool leftOpen = false;
                if (i - 1 >= 0) {
                    int xl = xStart + (i - 1);
                    int yl = yStart - (i - 1);
                    if (grid[yl][xl] == 0) leftOpen = true;
                }
                bool rightOpen = false;
                if (j < len) {
                    int xr = xStart + j;
                    int yr = yStart - j;
                    if (grid[yr][xr] == 0) rightOpen = true;
                }
                score += patternScore(count, leftOpen, rightOpen);
                i = j;
            } else {
                ++i;
            }
        }
    }
    return score;
}

int SearchEngine::evaluate(const Board &board, Player myColor) const {
    // Evaluate the board as the difference between the current player's
    // pattern score and the opponent's pattern score.  A positive value
    // indicates that myColor has more or stronger threats on the board.
    Player opponent = (myColor == Player::Black ? Player::White : Player::Black);
    int myScore = evaluatePlayer(board, myColor);
    int oppScore = evaluatePlayer(board, opponent);
    return myScore - oppScore;
}

int SearchEngine::alphaBeta(Board &board, int depth, int alpha, int beta,
                  Player currentPlayer, Player myColor, int ply) {
    // This function implements a classic alpha–beta search with a
    // transposition table and various move ordering heuristics.  It
    // returns a score from the perspective of myColor.  The parameters
    // alpha and beta store the best scores found so far along the path
    // and allow pruning: if the current node's score is worse than the
    // existing alpha/beta window, further exploration can be skipped.
    // The parameter currentPlayer determines whose turn it is to move,
    // while ply is the depth from the root and is used for killer moves.

    // Check for time expiration early.
    if (timeUp()) {
        return 0;
    }
    // Depth limit or terminal evaluation.
    if (depth <= 0) {
        return evaluate(board, myColor);
    }
    // Check for immediate wins.  If myColor has five in a row, return a large
    // positive value.  If the opponent has five in a row, return a large
    // negative value.  We use a depth penalty to prefer shorter wins and
    // longer losses.
    if (board.checkWin(myColor)) {
        return 100000000 - (maxDepthReached - depth);
    }
    Player opponent = (myColor == Player::Black ? Player::White : Player::Black);
    if (board.checkWin(opponent)) {
        return -100000000 + (maxDepthReached - depth);
    }

    // Look up this position in the transposition table.
    uint64_t key = board.getHashKey();
    auto it = transTable.find(key);
    if (it != transTable.end()) {
        const TTEntry &entry = it->second;
        // Only use the entry if it was searched to at least the same depth.
        if (entry.depth >= depth) {
            if (entry.flag == 0) {
                return entry.score;
            } else if (entry.flag == 1) {
                // Lower bound: value >= entry.score
                if (entry.score > alpha) alpha = entry.score;
            } else if (entry.flag == 2) {
                // Upper bound: value <= entry.score
                if (entry.score < beta) beta = entry.score;
            }
            if (alpha >= beta) {
                return entry.score;
            }
        }
    }
    // Generate candidate moves.  If there are none, evaluate the position.
    auto candidateMoves = board.getCandidateMoves();
    if (candidateMoves.empty()) {
        return evaluate(board, myColor);
    }
    // Order the moves using heuristics to improve pruning.  Pass the
    // current ply so killer moves at this depth can be prioritized.
    auto ordered = orderMoves(board, currentPlayer, myColor, ply);
    // Keep track of the best value and best move found at this node.
    Move bestMove(-1, -1);
    int bestValue;
    int alphaOrig = alpha;
    int betaOrig = beta;
    if (currentPlayer == myColor) {
        bestValue = std::numeric_limits<int>::min();
        for (const auto &m : ordered) {
            if (timeUp()) break;
            board.makeMove(m.x, m.y);
            int val = alphaBeta(board, depth - 1, alpha, beta,
                                (currentPlayer == Player::Black ? Player::White : Player::Black), myColor, ply + 1);
            board.unmakeMove(m.x, m.y);
            if (timeUp()) {
                return 0;
            }
            if (val > bestValue) {
                bestValue = val;
                bestMove = m;
            }
            if (bestValue > alpha) {
                alpha = bestValue;
            }
            if (alpha >= beta) {
                // Beta cutoff: record killer move and update history heuristic.
                if (ply < MAX_PLY) {
                    if (!(killerMoves[ply][0].x == m.x && killerMoves[ply][0].y == m.y)) {
                        // Shift existing killer move to second slot.
                        killerMoves[ply][1] = killerMoves[ply][0];
                        killerMoves[ply][0] = m;
                    }
                }
                // Increase history heuristic for this move.  Deeper cutoffs get
                // a larger increment (depth squared).
                history.increment(m, depth);
                break;
            }
        }
    } else {
        bestValue = std::numeric_limits<int>::max();
        for (const auto &m : ordered) {
            if (timeUp()) break;
            board.makeMove(m.x, m.y);
            int val = alphaBeta(board, depth - 1, alpha, beta,
                                (currentPlayer == Player::Black ? Player::White : Player::Black), myColor, ply + 1);
            board.unmakeMove(m.x, m.y);
            if (timeUp()) {
                return 0;
            }
            if (val < bestValue) {
                bestValue = val;
                bestMove = m;
            }
            if (bestValue < beta) {
                beta = bestValue;
            }
            if (alpha >= beta) {
                // Alpha cutoff: record killer move and update history heuristic.
                if (ply < MAX_PLY) {
                    if (!(killerMoves[ply][0].x == m.x && killerMoves[ply][0].y == m.y)) {
                        killerMoves[ply][1] = killerMoves[ply][0];
                        killerMoves[ply][0] = m;
                    }
                }
                history.increment(m, depth);
                break;
            }
        }
    }
    // Store the result in the transposition table.
    int flag;
    if (bestValue <= alphaOrig) {
        // Fails high: an upper bound.
        flag = 2;
    } else if (bestValue >= betaOrig) {
        // Fails low: a lower bound.
        flag = 1;
    } else {
        // Exact value.
        flag = 0;
    }
    TTEntry newEntry;
    newEntry.depth = depth;
    newEntry.score = bestValue;
    newEntry.flag = flag;
    newEntry.bestMove = bestMove;
    // Enforce an upper bound on the number of transposition table entries
    // to keep memory usage under control during very long searches.
    if (transTable.size() >= TT_MAX_ENTRIES) {
        transTable.clear();
    }
    transTable[key] = newEntry;
    return bestValue;
}

Move SearchEngine::findBestMove(Board &board, Player myColor, int timeLimitMs) {
    // Set up the timer for this move.  The search will stop when
    // timeUp() becomes true.
    startTimer(timeLimitMs);
    // Clear the transposition table at the start of each search.  Using
    // a fresh table prevents reuse of stale entries from previous moves
    // and bounds the memory footprint.
    transTable.clear();
    // Reset the history heuristic table for this search.  History values
    // accumulate within a single search but are cleared between moves.
    history.reset();
    // Reset killer moves.  Mark all moves as invalid (-1,-1).
    for (int i = 0; i < MAX_PLY; ++i) {
        killerMoves[i][0] = Move(-1, -1);
        killerMoves[i][1] = Move(-1, -1);
    }
    // Optional opening book: if we are in the predetermined opening and it is
    // our turn to move as Black, select a hard-coded central move.
    Move bookMove;
    if (getOpeningMove(board, myColor, bookMove)) {
        return bookMove;
    }

    // --- Immediate tactical pre-search ---
    // Before engaging the deeper VCF/VCT threat solver and the full
    // alpha–beta search, perform a series of lightweight tactical
    // checks using the ThreatSolver.  The order of checks is:
    //   1. Immediate winning moves for myColor.
    //   2. Immediate winning moves for the opponent (blocks).
    //   3. Moves that create double threats for myColor.
    //   4. Moves that preempt an opponent’s impending double threat.
    // If any such tactical move exists, pick the best one using a
    // shallow static evaluation and play it immediately, skipping
    // deeper search.  This ensures that obvious tactics are never
    // missed by the search.
    {
        ThreatSolver solver;
        // Precompute opponent colour for use throughout the tactical
        // checks.  We compute this once to avoid redeclaring it in
        // nested scopes, which could lead to redefinition errors.
        Player opponent = (myColor == Player::Black ? Player::White : Player::Black);

        // 1. Immediate win for myColor
        auto myWins = solver.findImmediateWin(board, myColor);
        if (!myWins.empty()) {
            // Choose the best immediate winning move based on a static
            // evaluation.  Although any immediate win is sufficient,
            // selecting the move with the highest follow‑up value can
            // steer the engine towards better secondary outcomes (e.g.
            // creating more flexibility or limiting opponent options).
            Move bestM = myWins.front();
            int bestVal = std::numeric_limits<int>::min();
            // 'opponent' already defined above
            for (const auto &m : myWins) {
                board.makeMove(m.x, m.y);
                int val = evaluate(board, myColor);
                // Undo; evaluation of final position is enough.
                board.unmakeMove(m.x, m.y);
                if (val > bestVal) {
                    bestVal = val;
                    bestM = m;
                }
            }
            return bestM;
        }
        // 2. Immediate win for the opponent: must block.
        auto oppWins = solver.findImmediateWin(board, opponent);
        if (!oppWins.empty()) {
            // If multiple winning squares exist, pick one to block.  We
            // choose the block that yields the best static evaluation
            // and which does not leave the opponent with another
            // immediate win.  If blocking one square still leaves
            // another immediate win, we nevertheless pick the best
            // according to evaluation.
            Move bestBlock = oppWins.front();
            int bestVal = std::numeric_limits<int>::min();
            for (const auto &m : oppWins) {
                if (board.isOccupied(m.x, m.y)) continue;
                board.makeMove(m.x, m.y);
                // After blocking, evaluate the position for myColor.
                int val = evaluate(board, myColor);
                // Also penalize moves that still leave the opponent an
                // immediate win (another square).  We recompute
                // opponent immediate wins on the resulting board.
                auto nextOppWins = solver.findImmediateWin(board, opponent);
                if (!nextOppWins.empty()) {
                    // Heavy penalty for leaving a direct win.
                    val -= 100000000;
                }
                // Additionally penalize moves that leave the opponent
                // with an open four or open three using cost square
                // detection.  This helps the engine pick the most
                // resilient defensive square when multiple blocks exist.
                auto nextOppCost = computeCostSquares(board, opponent, /*allowThree=*/true);
                if (!nextOppCost.empty()) {
                    if (nextOppCost.size() == 1) {
                        val -= 10000000;
                    } else if (nextOppCost.size() == 2) {
                        val -= 8000000;
                    } else {
                        val -= 4000000;
                    }
                }
                board.unmakeMove(m.x, m.y);
                if (val > bestVal) {
                    bestVal = val;
                    bestBlock = m;
                }
            }
            return bestBlock;
        }
        // 3. Double threat for myColor: find moves that create two
        // immediate winning replies without allowing an immediate
        // opponent win.  These moves are extremely powerful and are
        // considered with high priority.
        auto myDoubleThreats = solver.findDoubleThreatWinningMove(board, myColor);
        if (!myDoubleThreats.empty()) {
            // Choose the best double‑threat move by static evaluation.
            Move bestDT = myDoubleThreats.front();
            int bestVal = std::numeric_limits<int>::min();
            for (const auto &m : myDoubleThreats) {
                if (board.isOccupied(m.x, m.y)) continue;
                board.makeMove(m.x, m.y);
                // Evaluate the resulting position from myColor’s
                // perspective.  Favour moves that also restrict
                // opponent threats.
                int val = evaluate(board, myColor);
                // Penalize moves that leave the opponent with any
                // immediate win or cost squares.  Since
                // findDoubleThreatWinningMove already filtered out
                // positions with an immediate opponent win, we only
                // consider cost squares here.
                auto nextOppCost = computeCostSquares(board, opponent, /*allowThree=*/true);
                if (!nextOppCost.empty()) {
                    if (nextOppCost.size() == 1) {
                        val -= 10000000;
                    } else if (nextOppCost.size() == 2) {
                        val -= 8000000;
                    } else {
                        val -= 4000000;
                    }
                }
                board.unmakeMove(m.x, m.y);
                if (val > bestVal) {
                    bestVal = val;
                    bestDT = m;
                }
            }
            return bestDT;
        }
        // 4. Detect and preempt opponent double threats.  Obtain a
        // list of squares which, if played now, will prevent the
        // opponent from creating a move with two immediate winning
        // replies on their next turn.  If none exist, the vector is
        // empty.
        auto oppDoubleBlocks = solver.detectOpponentImpendingDoubleThreat(board, opponent);
        if (!oppDoubleBlocks.empty()) {
            // Choose the best preventive move using static evaluation
            // similar to blocking immediate wins.  We penalize moves
            // that leave the opponent with an immediate win or strong
            // threat after our move.
            Move bestDef = oppDoubleBlocks.front();
            int bestVal = std::numeric_limits<int>::min();
            for (const auto &m : oppDoubleBlocks) {
                if (board.isOccupied(m.x, m.y)) continue;
                board.makeMove(m.x, m.y);
                int val = evaluate(board, myColor);
                // Penalize positions where the opponent still has an
                // immediate win.
                auto nextOppWins = solver.findImmediateWin(board, opponent);
                if (!nextOppWins.empty()) {
                    val -= 100000000;
                }
                // Penalize positions that leave open four / open three
                // threats for the opponent.
                auto nextOppCost = computeCostSquares(board, opponent, /*allowThree=*/true);
                if (!nextOppCost.empty()) {
                    if (nextOppCost.size() == 1) {
                        val -= 10000000;
                    } else if (nextOppCost.size() == 2) {
                        val -= 8000000;
                    } else {
                        val -= 4000000;
                    }
                }
                board.unmakeMove(m.x, m.y);
                if (val > bestVal) {
                    bestVal = val;
                    bestDef = m;
                }
            }
            return bestDef;
        }
    }
    // --- Threat solver ---
    // Attempt to find a short forcing winning sequence before
    // performing a full alpha–beta search.  The threat solver
    // explores sequences of continuous threats (VCF and VCT) up
    // to a limited depth.  If it finds a forced win, the first
    // move of the winning line is returned immediately.
    {
        ThreatSolver solver;
        Move force;
        // Use a modest depth (e.g. 4) to keep the solver fast.  This
        // depth counts attacker moves, so it examines sequences up to
        // four moves long.  The allowThree flag enables VCT (three
        //‑stone threats) as well as VCF.
        if (solver.findThreatSequence(board, myColor, force, /*allowThree=*/true, /*maxDepth=*/4)) {
            return force;
        }
    }

    // --- Opponent threat detection ---
    // If the opponent currently has an open four or open three (two open ends),
    // we must play a defensive move immediately.  Compute all cost squares
    // (defensive squares) for the opponent.  If there is exactly one such
    // square, it is a must‑block; return it directly.  If multiple cost
    // squares exist (e.g. multiple threats), evaluate each defensive
    // candidate using a simple static evaluation and choose the best.  This
    // prevents the engine from ignoring an opponent’s open three and losing
    // immediately.
    {
        Player opponent = (myColor == Player::Black ? Player::White : Player::Black);
        auto oppCost = computeCostSquares(board, opponent, /*allowThree=*/true);
        if (!oppCost.empty()) {
            // Single defensive square: block immediately.
            if (oppCost.size() == 1) {
                return oppCost.front();
            } else {
                // Choose the defensive move that yields the best evaluation.
                Move bestDef = oppCost.front();
                int bestVal = std::numeric_limits<int>::min();
                for (const auto &m : oppCost) {
                    // Skip occupied squares (should not happen).
                    if (board.isOccupied(m.x, m.y)) continue;
                    board.makeMove(m.x, m.y);
                    // Simple evaluation of the resulting position.  We do not
                    // launch a full search here to save time; we rely on
                    // static evaluation to compare defensive candidates.
                    int val = evaluate(board, myColor);
                    // If the opponent still has an open four after this move,
                    // penalize it heavily to steer away from doomed moves.
                    auto nextOppCost = computeCostSquares(board, opponent, /*allowThree=*/true);
                    if (!nextOppCost.empty()) {
                        // If the next threat has only one cost square, the
                        // opponent can still win on the next move.  Penalize
                        // these defensive moves.
                        if (nextOppCost.size() == 1) {
                            val -= 100000000;
                        }
                    }
                    board.unmakeMove(m.x, m.y);
                    if (val > bestVal) {
                        bestVal = val;
                        bestDef = m;
                    }
                }
                return bestDef;
            }
        }
    }
    Move bestMove(-1, -1);
    // Generate and order root moves.  These moves will be re-ordered
    // between iterations based on the values returned by the search.
    auto rootMoves = orderMoves(board, myColor, myColor, 0);
    if (rootMoves.empty()) {
        return bestMove;
    }
    int bestVal = std::numeric_limits<int>::min();
    // Begin iterative deepening: increase the search depth one ply at a time.
    for (int depth = 1; ; ++depth) {
        if (timeUp()) break;
        maxDepthReached = depth;
        Move currentBestMove = rootMoves.front();
        int currentBestVal = std::numeric_limits<int>::min();
        // Track scores for all root moves at this depth so we can reuse them
        // when reordering for the next iteration instead of re-searching.
        std::vector<std::pair<int, Move>> scored;
        scored.reserve(rootMoves.size());

        for (const auto &m : rootMoves) {
            if (timeUp()) break;
            board.makeMove(m.x, m.y);
            int val = alphaBeta(board,
                                depth - 1,
                                std::numeric_limits<int>::min() + 1,
                                std::numeric_limits<int>::max() - 1,
                                (myColor == Player::Black ? Player::White : Player::Black),
                                myColor,
                                1);
            board.unmakeMove(m.x, m.y);
            if (timeUp()) break;

            scored.emplace_back(val, m);

            // If the returned value indicates a certain win (large positive),
            // we can return this move immediately.
            if (val > 90000000) {
                return m;
            }
            if (val > currentBestVal) {
                currentBestVal = val;
                currentBestMove = m;
            }
        }

        if (!timeUp() && !scored.empty()) {
            bestVal = currentBestVal;
            bestMove = currentBestMove;
            // Reorder root moves based on their values for the next iteration.
            // Moves that scored better are tried first in deeper searches.
            std::sort(scored.begin(), scored.end(),
                      [](const std::pair<int, Move> &a, const std::pair<int, Move> &b) {
                          return a.first > b.first;
                      });
            rootMoves.clear();
            rootMoves.reserve(scored.size());
            for (auto &p : scored) {
                rootMoves.push_back(p.second);
            }
        } else {
            break;
        }
    }
    return bestMove;
}

std::vector<Move> SearchEngine::orderMoves(Board &board, Player currentPlayer, Player myColor, int ply) {
    // Generate candidate moves within the board's bounding box and near
    // existing stones.  These moves form the basis for move ordering.
    auto moves = board.getCandidateMoves();
    std::vector<std::pair<int, Move>> scored;
    scored.reserve(moves.size());
    Player opponent = (currentPlayer == Player::Black ? Player::White : Player::Black);
    for (const auto &m : moves) {
        int score = 0;
        // Make the move and evaluate consequences.
        board.makeMove(m.x, m.y);
        // Check for immediate win for the player who plays this move.
        bool winForCurrent = board.checkWin(currentPlayer);
        // Check if this move would allow the opponent to win on their next turn.
        bool winForOpp = board.checkWin(opponent);
        // Evaluate board from myColor perspective; larger is better for myColor.
        int evalScore = evaluate(board, myColor);
        // Determine if this move leaves the opponent with an immediate
        // threat (open four or open three).  If so, penalize the move
        // to discourage ignoring opponent threats.  Compute cost squares
        // for the opponent after this move.  We use allowThree = true
        // so that open threes are detected.
        auto oppCostAfter = computeCostSquares(board, opponent, /*allowThree=*/true);
        board.unmakeMove(m.x, m.y);
        // Scoring heuristic:
        //  * If the move wins immediately for the current player, assign a
        //    very large score to ensure it is tried first.
        if (winForCurrent) {
            score = 100000000;
        } else if (winForOpp) {
            // If the move inadvertently allows the opponent to win, penalize
            // heavily to avoid self‑destruction.
            score = -10000000;
        } else {
            // Start with the static evaluation score.
            score = evalScore;
            // If this move leaves the opponent with cost squares (i.e. a
            // threatened win on their next turn), penalize it.  We distinguish
            // between simple fours (exactly one defensive square), open fours
            // (two defensive squares) and open threes or weaker threats (three
            // or more defensive squares).  A closed or broken four with only
            // one empty end is the most urgent to block; an open four still
            // allows the opponent to win in two ways; an open three is less
            // urgent but still dangerous.  We assign decreasing penalties to
            // reflect these differences.
            if (!oppCostAfter.empty()) {
                size_t n = oppCostAfter.size();
                if (n == 1) {
                    // Single defensive square (simple four).
                    score -= 10000000;
                } else if (n == 2) {
                    // Two defensive squares (open four).
                    score -= 8000000;
                } else {
                    // More defensive squares (open three or weaker).
                    score -= 4000000;
                }
            }
        }
        // Additional heuristic: prefer moves closer to the center.
        int dx = m.x - 5;
        int dy = m.y - 5;
        score -= (dx * dx + dy * dy);
        // Killer move heuristic: if this move is one of the recorded killer moves
        // at the current search ply, add a large bonus.  The first killer move
        // receives a larger bonus than the second.  Killer moves are ones that
        // previously caused a beta or alpha cutoff at this depth and are good
        // candidates for pruning.
        const int KILLER_BONUS1 = 1000000;
        const int KILLER_BONUS2 = 500000;
        if (ply < MAX_PLY) {
            if (killerMoves[ply][0].x == m.x && killerMoves[ply][0].y == m.y) {
                score += KILLER_BONUS1;
            } else if (killerMoves[ply][1].x == m.x && killerMoves[ply][1].y == m.y) {
                score += KILLER_BONUS2;
            }
        }
        // History heuristic: add the history table value for this move.
        // Moves that have frequently caused cutoffs in this search will be
        // tried earlier.  Deeper cutoffs contribute more to the history
        // table because increment() adds depth².
        score += history.get(m);
        scored.push_back({score, m});
    }
    // Sort descending by heuristic score so the best candidates appear first.
    std::sort(scored.begin(), scored.end(), [](const std::pair<int, Move> &a, const std::pair<int, Move> &b) {
        return a.first > b.first;
    });
    std::vector<Move> ordered;
    ordered.reserve(scored.size());
    for (auto &p : scored) {
        ordered.push_back(p.second);
    }
    return ordered;
}

// Compute cost squares for a given player on the board.  This function
// identifies immediate threats (open fours and optionally open threes)
// created by the specified player and returns the squares where the
// opponent must play to prevent an immediate win.  It duplicates the
// logic from ThreatSolver::computeCostSquares so that the search
// engine can independently detect threats without exposing internal
// solver state.
std::vector<Move> SearchEngine::computeCostSquares(const Board &board,
                                                   Player player,
                                                   bool allowThree) const {
    // This function identifies “cost” squares: points where the opponent must
    // play to avoid an immediate five from the specified player.  It
    // recognises both simple fours (count >= 4 contiguous stones with at
    // least one open end) and non‑standard open four patterns where four
    // stones are separated by empty cells but can still be extended to five
    // in exactly one or two ways.  To avoid over‑detecting, it only marks
    // those empty cells which, when filled by the attacking player, would
    // create a contiguous sequence of five stones.  If allowThree is true,
    // it also marks empty cells at both ends of a run of exactly three
    // contiguous stones (open threes).  We track visited cells to avoid
    // duplicates across lines and directions.
    bool seen[12][12];
    for (int y = 0; y < 12; ++y) {
        for (int x = 0; x < 12; ++x) {
            seen[y][x] = false;
        }
    }
    std::vector<Move> result;
    int targetState = (player == Player::Black ? 1 : 2);
    int oppState    = (targetState == 1 ? 2 : 1);
    auto addCost = [&](int x, int y) {
        if (x >= 0 && x < 12 && y >= 0 && y < 12) {
            if (!seen[y][x] && board.getCellState(x, y) == 0) {
                seen[y][x] = true;
                result.emplace_back(x, y);
            }
        }
    };
    // Helper to test whether filling (x,y) would create a contiguous
    // horizontal sequence of at least five target stones inside the
    // sub‑segment [start,end).  This checks left and right of the
    // candidate position within the limits.
    auto wouldMakeFiveRow = [&](int y, int start, int end, int x) {
        int left = 0;
        for (int lx = x - 1; lx >= start; --lx) {
            if (board.getCellState(lx, y) == targetState) {
                ++left;
            } else {
                break;
            }
        }
        int right = 0;
        for (int rx = x + 1; rx < end; ++rx) {
            if (board.getCellState(rx, y) == targetState) {
                ++right;
            } else {
                break;
            }
        }
        return (left + right + 1 >= 5);
    };
    // Helper for vertical, diagonal and anti‑diagonal will be defined later.
    // --- Rows ---
    for (int y = 0; y < 12; ++y) {
        for (int x = 0; x < 12; ) {
            // If we encounter an opponent stone, skip it and continue.
            if (board.getCellState(x, y) == oppState) {
                ++x;
                continue;
            }
            int start = x;
            while (x < 12 && board.getCellState(x, y) != oppState) ++x;
            int end = x;
            if (end - start >= 5) {
                // 1. Detect contiguous runs of player's stones.
                int i = start;
                while (i < end) {
                    if (board.getCellState(i, y) == targetState) {
                        int j = i;
                        while (j < end && board.getCellState(j, y) == targetState) ++j;
                        int count = j - i;
                        bool leftOpen = (i - 1 >= start && board.getCellState(i - 1, y) == 0);
                        bool rightOpen = (j < end && board.getCellState(j, y) == 0);
                        if (count >= 4) {
                            if (leftOpen) addCost(i - 1, y);
                            if (rightOpen) addCost(j, y);
                        } else if (allowThree && count == 3) {
                            if (leftOpen && rightOpen) {
                                addCost(i - 1, y);
                                addCost(j, y);
                            }
                        }
                        i = j;
                    } else {
                        ++i;
                    }
                }
                // 2. Detect non‑contiguous open fours: exactly four stones in this
                // segment.  For each empty cell, test if filling it would
                // create a contiguous run of five.
                int playerCount = 0;
                for (int u = start; u < end; ++u) {
                    if (board.getCellState(u, y) == targetState) playerCount++;
                }
                if (playerCount == 4) {
                    for (int u = start; u < end; ++u) {
                        if (board.getCellState(u, y) == 0) {
                            if (wouldMakeFiveRow(y, start, end, u)) {
                                addCost(u, y);
                            }
                        }
                    }
                }
            }
        }
    }
    // --- Columns ---
    // Helper to test if filling (x,y) would create a vertical five within
    // [start,end) segment on column x.
    auto wouldMakeFiveCol = [&](int x, int start, int end, int y) {
        int up = 0;
        for (int ly = y - 1; ly >= start; --ly) {
            if (board.getCellState(x, ly) == targetState) {
                ++up;
            } else {
                break;
            }
        }
        int down = 0;
        for (int ry = y + 1; ry < end; ++ry) {
            if (board.getCellState(x, ry) == targetState) {
                ++down;
            } else {
                break;
            }
        }
        return (up + down + 1 >= 5);
    };
    for (int x = 0; x < 12; ++x) {
        for (int y = 0; y < 12; ) {
            // Skip opponent stones to avoid zero-length segments.
            if (board.getCellState(x, y) == oppState) {
                ++y;
                continue;
            }
            int start = y;
            // Advance y until an opponent stone is found or board edge.
            while (y < 12 && board.getCellState(x, y) != oppState) ++y;
            int end = y;
            int len = end - start;
            if (len >= 5) {
                int i = start;
                while (i < end) {
                    if (board.getCellState(x, i) == targetState) {
                        int j = i;
                        while (j < end && board.getCellState(x, j) == targetState) ++j;
                        int count = j - i;
                        bool leftOpen = (i - 1 >= start && board.getCellState(x, i - 1) == 0);
                        bool rightOpen = (j < end && board.getCellState(x, j) == 0);
                        if (count >= 4) {
                            if (leftOpen) addCost(x, i - 1);
                            if (rightOpen) addCost(x, j);
                        } else if (allowThree && count == 3) {
                            if (leftOpen && rightOpen) {
                                addCost(x, i - 1);
                                addCost(x, j);
                            }
                        }
                        i = j;
                    } else {
                        ++i;
                    }
                }
                int playerCount = 0;
                for (int v = start; v < end; ++v) {
                    if (board.getCellState(x, v) == targetState) playerCount++;
                }
                if (playerCount == 4) {
                    for (int v = start; v < end; ++v) {
                        if (board.getCellState(x, v) == 0) {
                            if (wouldMakeFiveCol(x, start, end, v)) {
                                addCost(x, v);
                            }
                        }
                    }
                }
            }
        }
    }
    // --- Main diagonals (top‑left to bottom‑right) ---
    // Helper to test if filling a cell on a diagonal would create a five.
    auto wouldMakeFiveDiag = [&](int xStart, int yStart, int start, int end, int pos) {
        // pos is offset from start within this segment
        int x = xStart + pos;
        int y = yStart + pos;
        int left = 0;
        for (int k = pos - 1; k >= start; --k) {
            int xi = xStart + k;
            int yi = yStart + k;
            if (board.getCellState(xi, yi) == targetState) {
                ++left;
            } else {
                break;
            }
        }
        int right = 0;
        for (int k = pos + 1; k < end; ++k) {
            int xi = xStart + k;
            int yi = yStart + k;
            if (board.getCellState(xi, yi) == targetState) {
                ++right;
            } else {
                break;
            }
        }
        return (left + right + 1 >= 5);
    };
    for (int diag = -11; diag <= 11; ++diag) {
        int xStart = std::max(0, diag);
        int yStart = std::max(0, -diag);
        int len = std::min(12 - xStart, 12 - yStart);
        for (int i = 0; i < len; ) {
            // Skip opponent stones to avoid zero-length segments.
            if (board.getCellState(xStart + i, yStart + i) == oppState) {
                ++i;
                continue;
            }
            int start = i;
            while (i < len && board.getCellState(xStart + i, yStart + i) != oppState) ++i;
            int end = i;
            if (end - start >= 5) {
                int j = start;
                while (j < end) {
                    int xi = xStart + j;
                    int yi = yStart + j;
                    if (board.getCellState(xi, yi) == targetState) {
                        int k = j;
                        while (k < end && board.getCellState(xStart + k, yStart + k) == targetState) ++k;
                        int count = k - j;
                        bool leftOpen = (j - 1 >= start && board.getCellState(xStart + (j - 1), yStart + (j - 1)) == 0);
                        bool rightOpen = (k < end && board.getCellState(xStart + k, yStart + k) == 0);
                        if (count >= 4) {
                            if (leftOpen) addCost(xStart + (j - 1), yStart + (j - 1));
                            if (rightOpen) addCost(xStart + k, yStart + k);
                        } else if (allowThree && count == 3) {
                            if (leftOpen && rightOpen) {
                                addCost(xStart + (j - 1), yStart + (j - 1));
                                addCost(xStart + k, yStart + k);
                            }
                        }
                        j = k;
                    } else {
                        ++j;
                    }
                }
                int playerCount = 0;
                for (int t = start; t < end; ++t) {
                    if (board.getCellState(xStart + t, yStart + t) == targetState) playerCount++;
                }
                if (playerCount == 4) {
                    for (int t = start; t < end; ++t) {
                        int xcur = xStart + t;
                        int ycur = yStart + t;
                        if (board.getCellState(xcur, ycur) == 0) {
                            if (wouldMakeFiveDiag(xStart, yStart, start, end, t)) {
                                addCost(xcur, ycur);
                            }
                        }
                    }
                }
            }
        }
    }
    // --- Anti‑diagonals (top‑right to bottom‑left) ---
    // Helper to test if filling a cell on an anti‑diagonal would create a five.
    auto wouldMakeFiveAnti = [&](int xStart, int yStart, int start, int end, int pos) {
        int x = xStart + pos;
        int y = yStart - pos;
        int left = 0;
        for (int k = pos - 1; k >= start; --k) {
            int xi = xStart + k;
            int yi = yStart - k;
            if (board.getCellState(xi, yi) == targetState) {
                ++left;
            } else {
                break;
            }
        }
        int right = 0;
        for (int k = pos + 1; k < end; ++k) {
            int xi = xStart + k;
            int yi = yStart - k;
            if (board.getCellState(xi, yi) == targetState) {
                ++right;
            } else {
                break;
            }
        }
        return (left + right + 1 >= 5);
    };
    for (int sum = 0; sum <= 22; ++sum) {
        int xStart = std::max(0, sum - 11);
        int yStart = std::min(11, sum);
        int len = std::min(yStart + 1, 12 - xStart);
        for (int i = 0; i < len; ) {
            // Skip opponent stones to avoid zero-length segments.
            if (board.getCellState(xStart + i, yStart - i) == oppState) {
                ++i;
                continue;
            }
            int start = i;
            while (i < len && board.getCellState(xStart + i, yStart - i) != oppState) ++i;
            int end = i;
            if (end - start >= 5) {
                int j = start;
                while (j < end) {
                    int xi = xStart + j;
                    int yi = yStart - j;
                    if (board.getCellState(xi, yi) == targetState) {
                        int k = j;
                        while (k < end && board.getCellState(xStart + k, yStart - k) == targetState) ++k;
                        int count = k - j;
                        bool leftOpen = (j - 1 >= start && board.getCellState(xStart + (j - 1), yStart - (j - 1)) == 0);
                        bool rightOpen = (k < end && board.getCellState(xStart + k, yStart - k) == 0);
                        if (count >= 4) {
                            if (leftOpen) addCost(xStart + (j - 1), yStart - (j - 1));
                            if (rightOpen) addCost(xStart + k, yStart - k);
                        } else if (allowThree && count == 3) {
                            if (leftOpen && rightOpen) {
                                addCost(xStart + (j - 1), yStart - (j - 1));
                                addCost(xStart + k, yStart - k);
                            }
                        }
                        j = k;
                    } else {
                        ++j;
                    }
                }
                int playerCount = 0;
                for (int t = start; t < end; ++t) {
                    int xcur = xStart + t;
                    int ycur = yStart - t;
                    if (board.getCellState(xcur, ycur) == targetState) playerCount++;
                }
                if (playerCount == 4) {
                    for (int t = start; t < end; ++t) {
                        int xcur = xStart + t;
                        int ycur = yStart - t;
                        if (board.getCellState(xcur, ycur) == 0) {
                            if (wouldMakeFiveAnti(xStart, yStart, start, end, t)) {
                                addCost(xcur, ycur);
                            }
                        }
                    }
                }
            }
        }
    }
    return result;
}

} // namespace gomoku