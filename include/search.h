#include "search_engine.h"

#include <algorithm>
#include <cmath>

namespace gomoku {

namespace {
// Global per-search soft time budget in milliseconds, used by checkStopCondition.
// It is set from SearchEngine::searchBestMove and may be temporarily increased
// by panic mode inside iterativeDeepening.
std::uint64_t g_timeLimitMs = 0;

// Simple helper to flip the side to move.
inline Player opposite(Player p) {
    return (p == Player::Black) ? Player::White : Player::Black;
}
} // namespace

// =====================
// Constructor / public API
// =====================

SearchEngine::SearchEngine(Board&           board,
                           IEvaluator&      evaluator,
                           IThreatSolver*   threatSolver,
                           IHistoryHeuristic* historyHeuristic)
    : board_(board),
      evaluator_(evaluator),
      threatSolver_(threatSolver),
      history_(historyHeuristic),
      rootSide_(board.sideToMove()) {
    // Allocate a modest transposition table (~1M entries).
    const std::size_t ttSize = 1u << 20; // 1,048,576 entries
    tt_.resize(ttSize);
    clearTranspositionTable();
}

SearchResult SearchEngine::searchBestMove(const SearchLimits& limits) {
    limits_ = limits;
    startTime_ = Clock::now();
    nodes_ = qnodes_ = hashHits_ = 0;
    stop_ = false;
    rootSide_ = board_.sideToMove();

    // Reset external time budget used by checkStopCondition.
    g_timeLimitMs = limits_.timeLimitMs;

    // Clear previous search result.
    lastResult_ = SearchResult();

    // Optionally clear history heuristic between moves.
    if (history_) {
        history_->clear();
    }

    // First, let the threat solver try to prove an immediate forced win
    // for the side to move at the root.
    if (threatSolver_) {
        ThreatAnalysis rootThreat = threatSolver_->analyzeThreats(board_, rootSide_);
        if (rootThreat.attackerHasForcedWin) {
            lastResult_.isForcedWin  = true;
            lastResult_.isMate       = true;
            lastResult_.depthReached = 1;
            lastResult_.bestScore    = kMateScore;
            lastResult_.bestMove     = rootThreat.firstWinningMove;

            // Prefer full winning line if provided; otherwise at least
            // include the first winning move in the PV.
            if (!rootThreat.winningLine.empty()) {
                lastResult_.principalVariation = rootThreat.winningLine;
            } else if (!(rootThreat.firstWinningMove == Move())) {
                lastResult_.principalVariation.clear();
                lastResult_.principalVariation.push_back(rootThreat.firstWinningMove);
            }

            return lastResult_;
        }
    }

    // Run the main iterative deepening search.
    iterativeDeepening();

    // Mark timeout flag if we stopped due to time or node budget.
    if (stop_) {
        const bool timeExceeded =
            (g_timeLimitMs > 0 && elapsedMs() >= g_timeLimitMs);
        const bool nodeExceeded =
            (limits_.maxNodes > 0 && (nodes_ + qnodes_) >= limits_.maxNodes);
        lastResult_.isTimeout = timeExceeded || nodeExceeded;
    }

    lastResult_.nodes    = nodes_;
    lastResult_.qnodes   = qnodes_;
    lastResult_.hashHits = hashHits_;

    return lastResult_;
}

void SearchEngine::clearTranspositionTable() {
    for (auto& entry : tt_) {
        entry.key   = 0;
        entry.value = 0;
        entry.eval  = 0;
        entry.depth = -1;
        entry.type  = TTNodeType::Exact;
        entry.bestMove = Move();
    }
}

// =====================
// Transposition table helpers
// =====================

SearchEngine::TTEntry* SearchEngine::probeTT(std::uint64_t key) {
    if (tt_.empty()) return nullptr;
    std::size_t idx = static_cast<std::size_t>(key) % tt_.size();
    TTEntry& entry  = tt_[idx];
    if (entry.key == key && entry.depth >= 0) {
        return &entry;
    }
    return nullptr;
}

void SearchEngine::storeTT(std::uint64_t key,
                           EvalScore     value,
                           EvalScore     eval,
                           int           depth,
                           TTNodeType    type,
                           const Move&   bestMove) {
    if (tt_.empty()) return;
    std::size_t idx = static_cast<std::size_t>(key) % tt_.size();
    TTEntry& entry  = tt_[idx];

    // Simple replacement scheme: always replace if the slot is empty or
    // the new depth is greater or equal to the stored one.
    if (entry.depth <= depth || entry.key == 0) {
        entry.key      = key;
        entry.value    = value;
        entry.eval     = eval;
        entry.depth    = depth;
        entry.type     = type;
        entry.bestMove = bestMove;
    }
}

EvalScore SearchEngine::toTTScore(EvalScore score, int plyFromRoot) {
    // Normalize mate scores so that closer mates have larger magnitude.
    if (score >= kMateScore - 1000) {
        // Winning mate: increase score as we get closer to root.
        return score + plyFromRoot;
    }
    if (score <= -kMateScore + 1000) {
        // Losing mate: decrease score as we get closer to root.
        return score - plyFromRoot;
    }
    return score;
}

EvalScore SearchEngine::fromTTScore(EvalScore score, int plyFromRoot) {
    if (score >= kMateScore - 1000) {
        return score - plyFromRoot;
    }
    if (score <= -kMateScore + 1000) {
        return score + plyFromRoot;
    }
    return score;
}

// =====================
// Core search
// =====================

EvalScore SearchEngine::search(int       depth,
                               EvalScore alpha,
                               EvalScore beta,
                               int       ply,
                               bool      allowNull,
                               bool      inPV) {
    if (stop_) {
        return 0;
    }

    ++nodes_;
    checkStopCondition();
    if (stop_) {
        return 0;
    }

    const Player side   = board_.sideToMove();
    const Player prev   = opposite(side);
    const bool   isRoot = (ply == 0);

    // Check for an immediate win by the player who just moved.
    if (board_.checkWin(prev)) {
        // If the previous mover is the root side, it's a win; otherwise a loss.
        EvalScore score = (prev == rootSide_) ? (kMateScore - ply)
                                              : (-kMateScore + ply);
        return score;
    }

    // Depth reached: switch to quiescence search.
    if (depth <= 0) {
        return quiescence(alpha, beta, ply);
    }

    const EvalScore alphaOrig = alpha;

    const std::uint64_t key = board_.getHashKey();

    // Probe TT.
    Move     ttMove;
    TTEntry* ttEntry = probeTT(key);
    EvalScore ttEval = 0;

    if (ttEntry) {
        ++hashHits_;
        ttMove = ttEntry->bestMove;
        ttEval = ttEntry->eval;

        // Try using stored value if it is deep enough.
        if (ttEntry->depth >= depth) {
            EvalScore ttScore = fromTTScore(ttEntry->value, ply);
            switch (ttEntry->type) {
                case TTNodeType::Exact:
                    return ttScore;
                case TTNodeType::LowerBound:
                    if (ttScore > alpha) alpha = ttScore;
                    break;
                case TTNodeType::UpperBound:
                    if (ttScore < beta) beta = ttScore;
                    break;
            }
            if (alpha >= beta) {
                return ttScore;
            }
        }
    }

    // Static evaluation.
    EvalScore staticEval;
    if (ttEntry && ttEntry->eval != 0) {
        staticEval = ttEntry->eval;
    } else {
        staticEval = evaluator_.evaluate(board_, rootSide_);
    }

    // Threat analysis for the side to move.
    ThreatAnalysis threatInfo;
    if (threatSolver_) {
        threatInfo = threatSolver_->analyzeThreats(board_, side);
    }

    // Null-move pruning.
    if (limits_.enableNullMove && allowNull && canDoNullMove(threatInfo, depth, ply)) {
        EvalScore nullScore = nullMoveSearch(beta, beta, depth, ply);
        if (stop_) {
            return 0;
        }
        if (nullScore >= beta) {
            // Fail-high: position is so good that even skipping a move
            // still keeps it above beta.
            storeTT(key,
                    toTTScore(nullScore, ply),
                    staticEval,
                    depth,
                    TTNodeType::LowerBound,
                    Move());
            return nullScore;
        }
    }

    // Generate moves (possibly restricted by threat solver).
    std::vector<Move> moves = generateMoves(threatInfo);
    if (moves.empty()) {
        // No legal moves available: treat as draw.
        return kDrawScore;
    }

    // PV move hint: at root, we know the previous iteration's best move.
    Move pvMove;
    if (isRoot && !lastResult_.principalVariation.empty()) {
        pvMove = lastResult_.principalVariation.front();
    }

    // Order moves using TT, PV and history heuristic.
    orderMoves(side, moves, ttMove, pvMove, threatInfo);

    EvalScore bestScore = -kInfinity;
    Move      bestMove;
    bool      firstMove = true;

    for (const Move& move : moves) {
        MoveGuard guard(board_, move);
        if (!guard.isValid()) {
            continue; // Illegal/occupied cell.
        }

        EvalScore score;

        if (firstMove) {
            // First child: full-window search.
            score = -search(depth - 1, -beta, -alpha, ply + 1, true, inPV);
            firstMove = false;
        } else {
            // Principal Variation Search (PVS):
            // First try a zero-width window.
            score = -search(depth - 1, -alpha - 1, -alpha, ply + 1, true, false);
            if (!stop_ && score > alpha && score < beta) {
                // Re-search with full window if promising.
                score = -search(depth - 1, -beta, -alpha, ply + 1, true, inPV);
            }
        }

        if (stop_) {
            break;
        }

        if (score > bestScore) {
            bestScore = score;
            bestMove  = move;

            if (score > alpha) {
                alpha = score;
                if (history_ && isRoot) {
                    // Slightly reward PV moves at the root.
                    history_->recordPVMove(side, move, depth);
                }
            }
        }

        if (alpha >= beta) {
            // Beta cutoff.
            if (history_) {
                history_->recordBetaCutoff(side, move, depth);
            }
            break;
        }
    }

    // If we did not find any valid move (all illegal, etc.), treat as draw.
    if (bestScore == -kInfinity) {
        bestScore = kDrawScore;
    }

    // Store in TT.
    TTNodeType type;
    if (bestScore <= alphaOrig) {
        type = TTNodeType::UpperBound;
    } else if (bestScore >= beta) {
        type = TTNodeType::LowerBound;
    } else {
        type = TTNodeType::Exact;
    }

    storeTT(key,
            toTTScore(bestScore, ply),
            staticEval,
            depth,
            type,
            bestMove);

    return bestScore;
}

EvalScore SearchEngine::quiescence(EvalScore alpha,
                                   EvalScore beta,
                                   int       ply) {
    if (stop_) {
        return 0;
    }

    ++qnodes_;
    checkStopCondition();
    if (stop_) {
        return 0;
    }

    const Player side = board_.sideToMove();
    const Player prev = opposite(side);

    // Check for a win by the previous mover.
    if (board_.checkWin(prev)) {
        EvalScore score = (prev == rootSide_) ? (kMateScore - ply)
                                              : (-kMateScore + ply);
        return score;
    }

    // Static evaluation (stand-pat).
    EvalScore standPat = evaluator_.evaluate(board_, rootSide_);

    if (standPat >= beta) {
        return standPat;
    }

    if (standPat > alpha) {
        alpha = standPat;
    }

    // For Gomoku we typically don't have "noisy" captures to extend here,
    // so we just return the stand-pat / bounded score.
    return alpha;
}

// =====================
// Iterative deepening
// =====================

void SearchEngine::iterativeDeepening() {
    EvalScore prevScore = 0;
    bool      havePrev  = false;

    // Simple aspiration window parameters.
    const EvalScore aspWindow = 50;   // half-window size
    const EvalScore aspMax    = 400;  // maximum half-window after widening

    for (int depth = 1; depth <= limits_.maxDepth && !stop_; ++depth) {
        EvalScore alpha = -kInfinity;
        EvalScore beta  = kInfinity;

        if (havePrev) {
            alpha = std::max(prevScore - aspWindow, -kInfinity);
            beta  = std::min(prevScore + aspWindow,  kInfinity);
        }

        EvalScore score = 0;

        while (!stop_) {
            score = search(depth, alpha, beta, 0, true, true);

            if (stop_) {
                break;
            }

            if (score <= alpha && havePrev) {
                // Fail-low: widen window downwards.
                alpha = std::max(alpha - aspWindow, prevScore - aspMax);
                beta  = prevScore + aspWindow;
            } else if (score >= beta && havePrev) {
                // Fail-high: widen window upwards.
                beta  = std::min(beta + aspWindow, prevScore + aspMax);
                alpha = prevScore - aspWindow;
            } else {
                // Successful search within window.
                break;
            }
        }

        if (stop_) {
            break; // Use best result from previous completed depth.
        }

        prevScore = score;
        havePrev  = true;

        // Extract best move and PV from TT.
        TTEntry* rootEntry = probeTT(board_.getHashKey());
        if (rootEntry) {
            lastResult_.bestMove   = rootEntry->bestMove;
            lastResult_.bestScore  = fromTTScore(rootEntry->value, 0);
            lastResult_.depthReached = depth;
            lastResult_.isMate =
                (std::abs(lastResult_.bestScore) >= (kMateScore - 1000));

            lastResult_.principalVariation.clear();
            extractPrincipalVariation(lastResult_.principalVariation, depth);
        }

        lastResult_.nodes    = nodes_;
        lastResult_.qnodes   = qnodes_;
        lastResult_.hashHits = hashHits_;

        // If we've already found a forced mate, no need to search deeper.
        if (lastResult_.isMate) {
            break;
        }

        // Panic mode: if we are clearly losing and are close to time limit,
        // extend the effective time budget once.
        if (limits_.enablePanicMode && g_timeLimitMs == limits_.timeLimitMs) {
            if (elapsedMs() >= limits_.timeLimitMs && prevScore < -200) {
                g_timeLimitMs =
                    limits_.timeLimitMs + limits_.panicExtraTimeMs;
            }
        }
    }
}

// =====================
// Move generation & ordering
// =====================

std::vector<Move> SearchEngine::generateMoves(const ThreatAnalysis& threatInfo) {
    std::vector<Move> moves;

    // If the threat solver finds a direct winning move for the side to move,
    // prioritize it exclusively.
    if (threatSolver_ && threatInfo.attackerHasForcedWin) {
        const Move& winMove = threatInfo.firstWinningMove;
        if (!board_.isOccupied(winMove.x, winMove.y)) {
            moves.push_back(winMove);
            return moves;
        }
    }

    // If there are defensive moves, use them (filtering out occupied cells).
    if (threatSolver_ && !threatInfo.defensiveMoves.empty()) {
        for (const Move& m : threatInfo.defensiveMoves) {
            if (!board_.isOccupied(m.x, m.y)) {
                moves.push_back(m);
            }
        }
        if (!moves.empty()) {
            return moves;
        }
    }

    // Fallback: use board's candidate move generator.
    moves = board_.getCandidateMoves();
    return moves;
}

void SearchEngine::orderMoves(Player                sideToMove,
                              std::vector<Move>&    moves,
                              const Move&           ttMove,
                              const Move&           pvMove,
                              const ThreatAnalysis& threatInfo) {
    if (moves.empty()) return;

    struct ScoredMove {
        Move move;
        int  score;
    };

    std::vector<ScoredMove> scored;
    scored.reserve(moves.size());

    for (const Move& m : moves) {
        int score = 0;

        // Transposition table best move has very high priority.
        if (m == ttMove) {
            score += 1'000'000;
        }

        // Previous PV move is also highly prioritized.
        if (m == pvMove) {
            score += 900'000;
        }

        // Winning move from threat analysis.
        if (threatInfo.attackerHasForcedWin && m == threatInfo.firstWinningMove) {
            score += 800'000;
        }

        // Defensive moves from threat analysis.
        if (!threatInfo.defensiveMoves.empty()) {
            for (const Move& dm : threatInfo.defensiveMoves) {
                if (m == dm) {
                    score += 700'000;
                    break;
                }
            }
        }

        // History heuristic contribution.
        if (history_) {
            score += history_->getHistoryScore(sideToMove, m);
        }

        scored.push_back({m, score});
    }

    std::sort(scored.begin(), scored.end(),
              [](const ScoredMove& a, const ScoredMove& b) {
                  if (a.score != b.score) return a.score > b.score;
                  return a.move < b.move; // deterministic tie-breaker
              });

    for (std::size_t i = 0; i < moves.size(); ++i) {
        moves[i] = scored[i].move;
    }
}

void SearchEngine::extractPrincipalVariation(std::vector<Move>& outPV,
                                             int               maxDepth) {
    outPV.clear();

    // Follow TT best moves from the root.
    Board& b = board_;
    std::vector<Move> line;

    for (int ply = 0; ply < maxDepth; ++ply) {
        TTEntry* entry = probeTT(b.getHashKey());
        if (!entry) break;

        const Move& m = entry->bestMove;
        // Basic sanity: cell must be empty.
        if (b.isOccupied(m.x, m.y)) break;

        // Try making the move; if illegal, stop.
        if (!b.makeMove(m.x, m.y)) break;
        line.push_back(m);
    }

    // Undo moves to restore original board state.
    for (auto it = line.rbegin(); it != line.rend(); ++it) {
        b.unmakeMove(it->x, it->y);
    }

    outPV = std::move(line);
}

// =====================
// Null-move pruning
// =====================

bool SearchEngine::canDoNullMove(const ThreatAnalysis& threatInfo,
                                 int                   depth,
                                 int                   ply) const {
    if (!limits_.enableNullMove) return false;

    // Avoid null move too close to the leaves.
    if (depth < 3) return false;

    // Avoid null move at root for stability.
    if (ply == 0) return false;

    // If the current side has a forcing win or there are critical
    // defensive moves, be conservative and avoid null move.
    if (threatSolver_) {
        if (threatInfo.attackerHasForcedWin) return false;
        if (!threatInfo.defensiveMoves.empty()) return false;
    }

    return true;
}

EvalScore SearchEngine::nullMoveSearch(EvalScore alpha,
                                       EvalScore beta,
                                       int       depth,
                                       int       ply) {
    // Reduction amount: deeper searches get a slightly larger reduction.
    const int R = 2 + depth / 4;

    Player originalSide = board_.sideToMove();
    board_.setSideToMove(opposite(originalSide));

    EvalScore score =
        -search(depth - R - 1, -beta, -beta + 1, ply + 1, false, false);

    // Restore side to move.
    board_.setSideToMove(originalSide);

    return score;
}

// =====================
// Time management
// =====================

void SearchEngine::checkStopCondition() {
    if (stop_) return;

    if (limits_.maxNodes > 0 && (nodes_ + qnodes_) >= limits_.maxNodes) {
        stop_ = true;
        return;
    }

    if (g_timeLimitMs > 0 && elapsedMs() >= g_timeLimitMs) {
        stop_ = true;
    }
}

std::uint64_t SearchEngine::elapsedMs() const {
    auto now = Clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            now - startTime_)
            .count());
}

} // namespace gomoku