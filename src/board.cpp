// search_engine.cpp
//
// Implementation of the Gomoku SearchEngine defined in search_engine.h

#include "search.h"

#include <algorithm>
#include <cmath>
#include <cstddef>

namespace gomoku {

namespace {
    inline Player opponent(Player p) {
        return (p == Player::Black) ? Player::White : Player::Black;
    }

    // Board dimensions (matching board.h; keep in sync if board size changes)
    constexpr int kBoardSize = 12;

    inline bool isOnBoard(const Move& m) {
        return m.x >= 0 && m.x < kBoardSize && m.y >= 0 && m.y < kBoardSize;
    }
}

// =====================
// Constructor
// =====================

SearchEngine::SearchEngine(Board&           board,
                           IEvaluator&      evaluator,
                           IThreatSolver*   threatSolver,
                           IHistoryHeuristic* historyHeuristic)
    : board_(board),
      evaluator_(evaluator),
      threatSolver_(threatSolver),
      history_(historyHeuristic),
      rootSide_(board.sideToMove()),
      startTime_(Clock::now())
{
    // Choose a fixed TT size (power of two for cheap indexing).
    // 2^20 entries is a reasonable default for a 12x12 engine.
    constexpr std::size_t kTTSize = 1u << 20;
    tt_.resize(kTTSize);
    clearTranspositionTable();

    nodes_    = 0;
    qnodes_   = 0;
    hashHits_ = 0;
    stop_     = false;
}

// =====================
// Transposition table
// =====================

SearchEngine::TTEntry* SearchEngine::probeTT(std::uint64_t key) {
    if (tt_.empty()) return nullptr;
    std::size_t idx = static_cast<std::size_t>(key) & (tt_.size() - 1);

    TTEntry& entry = tt_[idx];
    if (entry.depth >= 0 && entry.key == key) {
        return &entry;
    }
    return nullptr;
}

void SearchEngine::storeTT(std::uint64_t key,
                           EvalScore     value,
                           EvalScore     eval,
                           int           depth,
                           TTNodeType    type,
                           const Move&   bestMove)
{
    if (tt_.empty()) return;
    std::size_t idx = static_cast<std::size_t>(key) & (tt_.size() - 1);

    TTEntry& entry = tt_[idx];

    // Simple "depth-preferred" replacement.
    if (entry.depth > depth && entry.key == key) {
        return;
    }

    entry.key   = key;
    entry.value = value;
    entry.eval  = eval;
    entry.depth = depth;
    entry.type  = type;
    entry.bestMove = bestMove;
}

EvalScore SearchEngine::toTTScore(EvalScore score, int plyFromRoot) {
    // Encode mate distances so they are comparable across plies.
    // Use a margin below kMateScore to detect mate scores.
    const EvalScore mateThreshold = kMateScore - 500;
    if (score > mateThreshold) {
        return score + plyFromRoot;
    } else if (score < -mateThreshold) {
        return score - plyFromRoot;
    }
    return score;
}

EvalScore SearchEngine::fromTTScore(EvalScore score, int plyFromRoot) {
    const EvalScore mateThreshold = kMateScore - 500;
    if (score > mateThreshold) {
        return score - plyFromRoot;
    } else if (score < -mateThreshold) {
        return score + plyFromRoot;
    }
    return score;
}

void SearchEngine::clearTranspositionTable() {
    for (auto& e : tt_) {
        e = TTEntry();   // depth is -1 by default
    }
}

// =====================
// Time / limits helpers
// =====================

std::uint64_t SearchEngine::elapsedMs() const {
    auto now = Clock::now();
    return static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime_).count()
    );
}

void SearchEngine::checkStopCondition() {
    if (stop_) return;

    if (limits_.maxNodes > 0) {
        std::uint64_t visited = nodes_ + qnodes_;
        if (visited >= limits_.maxNodes) {
            stop_ = true;
            return;
        }
    }

    std::uint64_t timeLimit = limits_.timeLimitMs;

    // Panic mode: if we already have a completed iteration that looks very bad,
    // extend time by panicExtraTimeMs (one-shot heuristic).
    if (limits_.enablePanicMode &&
        lastResult_.depthReached > 0 &&
        lastResult_.bestScore < -5000)   // arbitrary "losing" threshold
    {
        timeLimit += limits_.panicExtraTimeMs;
    }

    if (timeLimit > 0 && elapsedMs() >= timeLimit) {
        stop_ = true;
    }
}

// =====================
// Move generation / ordering
// =====================

std::vector<Move> SearchEngine::generateMoves(const ThreatAnalysis& threatInfo) {
    std::vector<Move> result;

    // If threat solver indicates opponent has a forcing win *but* there exist
    // defensive moves, restrict to those defensive moves only.
    if (threatSolver_ &&
        threatInfo.attackerHasForcedWin &&
        !threatInfo.defensiveMoves.empty())
    {
        result.reserve(threatInfo.defensiveMoves.size());
        for (const Move& m : threatInfo.defensiveMoves) {
            if (!isOnBoard(m)) continue;
            if (!board_.isOccupied(m.x, m.y)) {
                result.push_back(m);
            }
        }
        if (!result.empty()) {
            return result;
        }
        // If they were all illegal, fall back to normal candidates.
    }

    return board_.getCandidateMoves();
}

void SearchEngine::orderMoves(Player                sideToMove,
                              std::vector<Move>&    moves,
                              const Move&           ttMove,
                              const Move&           pvMove,
                              const ThreatAnalysis& threatInfo)
{
    // Precompute set of defensive moves (for small bonus).
    std::vector<Move> defensive = threatInfo.defensiveMoves;
    std::sort(defensive.begin(), defensive.end());

    auto isDefensive = [&defensive](const Move& m) {
        return std::binary_search(defensive.begin(), defensive.end(), m);
    };

    struct ScoredMove {
        Move      move;
        long long score;
    };

    std::vector<ScoredMove> scored;
    scored.reserve(moves.size());

    for (const Move& m : moves) {
        long long s = 0;

        // TT move first.
        if (m == ttMove) {
            s += 1'000'000;
        }
        // PV move (currently unused, but hooked up for future).
        if (isOnBoard(pvMove) && m == pvMove) {
            s += 500'000;
        }
        // Defensive moves when under threats.
        if (isDefensive(m)) {
            s += 200'000;
        }

        // History heuristic.
        if (history_) {
            s += history_->getHistoryScore(sideToMove, m);
        }

        // Slight preference for central moves (Manhattan distance).
        int dx = std::abs(m.x - kBoardSize / 2);
        int dy = std::abs(m.y - kBoardSize / 2);
        int manhattan = dx + dy;
        s -= manhattan * 10;

        scored.push_back({m, s});
    }

    std::sort(scored.begin(), scored.end(),
              [](const ScoredMove& a, const ScoredMove& b) {
                  return a.score > b.score;
              });

    for (std::size_t i = 0; i < moves.size(); ++i) {
        moves[i] = scored[i].move;
    }
}

// =====================
// Null-move pruning
// =====================

bool SearchEngine::canDoNullMove(const ThreatAnalysis& threatInfo,
                                 int                   depth,
                                 int                   ply) const
{
    if (!limits_.enableNullMove) return false;
    if (depth < 3) return false;    // need room for reduction
    if (ply == 0) return false;     // avoid at root
    if (threatInfo.attackerHasForcedWin) return false; // don't null when under attack
    return true;
}

EvalScore SearchEngine::nullMoveSearch(EvalScore alpha,
                                       EvalScore beta,
                                       int       depth,
                                       int       ply)
{
    if (stop_) return alpha;

    Player side = board_.getSideToMove();
    Player opp  = opponent(side);

    struct SideGuard {
        Board& b;
        Player saved;
        SideGuard(Board& board, Player s) : b(board), saved(s) {}
        ~SideGuard() { b.setSideToMove(saved); }
    } guard(board_, side);

    // "Make" a null move: just give the turn to the opponent.
    board_.setSideToMove(opp);

    int R = 2 + depth / 4;  // reduction
    int newDepth = depth - 1 - R;
    if (newDepth <= 0) {
        // Direct quiescence if too shallow.
        return -quiescence(-beta, -beta + 1, ply + 1);
    }

    EvalScore score = -search(newDepth, -beta, -beta + 1, ply + 1,
                              /*allowNull=*/false,
                              /*inPV=*/false);
    return score;
}

// =====================
// Quiescence search
// =====================

EvalScore SearchEngine::quiescence(EvalScore alpha,
                                   EvalScore beta,
                                   int       ply)
{
    checkStopCondition();
    if (stop_) return alpha;

    ++qnodes_;

    // Terminal: check for 5-in-a-row for either side.
    bool blackWin = board_.checkWin(Player::Black);
    bool whiteWin = board_.checkWin(Player::White);

    if (blackWin || whiteWin) {
        Player winner = blackWin ? Player::Black : Player::White;
        if (winner == rootSide_) {
            return kMateScore - ply;
        } else {
            return -kMateScore + ply;
        }
    }

    EvalScore standPat = evaluator_.evaluate(board_, rootSide_);

    if (standPat >= beta) {
        return beta;
    }
    if (standPat > alpha) {
        alpha = standPat;
    }

    // For now we do not generate tactical extensions (no captures in Gomoku).
    return alpha;
}

// =====================
// Core PVS alpha-beta search
// =====================

EvalScore SearchEngine::search(int       depth,
                               EvalScore alpha,
                               EvalScore beta,
                               int       ply,
                               bool      allowNull,
                               bool      inPV)
{
    checkStopCondition();
    if (stop_) return alpha;

    ++nodes_;

    Player side = board_.getSideToMove();
    Player opp  = opponent(side);

    // Terminal win detection first.
    bool blackWin = board_.checkWin(Player::Black);
    bool whiteWin = board_.checkWin(Player::White);

    if (blackWin || whiteWin) {
        Player winner = blackWin ? Player::Black : Player::White;
        if (winner == rootSide_) {
            return kMateScore - ply;
        } else {
            return -kMateScore + ply;
        }
    }

    // Leaf: go to quiescence.
    if (depth <= 0) {
        return quiescence(alpha, beta, ply);
    }

    std::uint64_t key = board_.getHashKey();
    TTEntry* tte = probeTT(key);
    Move ttMove;          // best move from TT if available
    EvalScore staticEval = 0;
    bool hasStaticEval   = false;

    if (tte) {
        ++hashHits_;
        ttMove = tte->bestMove;
        EvalScore ttScore = fromTTScore(tte->value, ply);

        if (tte->eval != 0) {
            staticEval   = tte->eval;
            hasStaticEval = true;
        }

        if (tte->depth >= depth) {
            // Use stored bounds.
            switch (tte->type) {
                case TTNodeType::Exact:
                    return ttScore;
                case TTNodeType::LowerBound:
                    if (ttScore >= beta) {
                        return ttScore;
                    }
                    alpha = std::max(alpha, ttScore);
                    break;
                case TTNodeType::UpperBound:
                    if (ttScore <= alpha) {
                        return ttScore;
                    }
                    beta = std::min(beta, ttScore);
                    break;
            }
            if (alpha >= beta) {
                return ttScore;
            }
        }
    }

    // Threat analysis for the opponent (they are the attacker).
    ThreatAnalysis threatInfo;
    if (threatSolver_) {
        threatInfo = threatSolver_->analyzeThreats(board_, opp);

        // If opponent has a forced win and we have *no* defensive moves,
        // this position is theoretically lost for 'side'.
        if (threatInfo.attackerHasForcedWin &&
            threatInfo.defensiveMoves.empty())
        {
            EvalScore score = (opp == rootSide_)
                              ? (kMateScore - ply)
                              : (-kMateScore + ply);
            return score;
        }
    }

    // Optional null-move pruning.
    if (allowNull && canDoNullMove(threatInfo, depth, ply)) {
        EvalScore nullScore = nullMoveSearch(alpha, beta, depth, ply);
        if (stop_) return alpha;
        if (nullScore >= beta) {
            // Null move says this position is so good that we don't need
            // to search further (fail-high).
            return nullScore;
        }
    }

    // Generate candidate moves (possibly restricted to defensive moves).
    std::vector<Move> moves = generateMoves(threatInfo);

    // If no legal moves, treat as draw.
    if (moves.empty()) {
        return kDrawScore;
    }

    // Ensure we have a static evaluation if needed for TT storage.
    if (!hasStaticEval) {
        staticEval = evaluator_.evaluate(board_, rootSide_);
        hasStaticEval = true;
    }

    // Move ordering.
    Move pvMove; // currently unused (empty)
    orderMoves(side, moves, ttMove, pvMove, threatInfo);

    EvalScore originalAlpha = alpha;
    EvalScore bestScore     = -kInfinity;
    Move      bestMoveLocal;
    bool      foundPV       = false;

    for (const Move& m : moves) {
        MoveGuard guard(board_, m);
        if (!guard.isValid()) {
            continue; // should not happen, but be safe
        }

        EvalScore score;

        if (!foundPV) {
            // First child: full window (PV search).
            score = -search(depth - 1, -beta, -alpha, ply + 1,
                            /*allowNull=*/true,
                            /*inPV=*/inPV);
        } else {
            // PVS re-search with zero-width window.
            score = -search(depth - 1, -alpha - 1, -alpha, ply + 1,
                            /*allowNull=*/true,
                            /*inPV=*/false);
            if (!stop_ && score > alpha && score < beta) {
                // Failed high; re-search with full window.
                score = -search(depth - 1, -beta, -alpha, ply + 1,
                                /*allowNull=*/true,
                                /*inPV=*/inPV);
            }
        }

        if (stop_) return alpha;

        if (score > bestScore) {
            bestScore     = score;
            bestMoveLocal = m;
        }

        if (score > alpha) {
            alpha   = score;
            foundPV = true;
        }

        if (alpha >= beta) {
            // Beta cutoff: record in history.
            if (history_) {
                history_->recordBetaCutoff(side, m, depth);
            }
            break;
        }
    }

    // Store in TT.
    TTNodeType type;
    if (bestScore <= originalAlpha) {
        type = TTNodeType::UpperBound;
    } else if (bestScore >= beta) {
        type = TTNodeType::LowerBound;
    } else {
        type = TTNodeType::Exact;
    }

    if (hasStaticEval) {
        storeTT(key,
                toTTScore(bestScore, ply),
                staticEval,
                depth,
                type,
                bestMoveLocal);
    }

    return bestScore;
}

// =====================
// PV extraction
// =====================

void SearchEngine::extractPrincipalVariation(std::vector<Move>& outPV,
                                             int               maxDepth)
{
    outPV.clear();
    std::vector<Move> applied;

    for (int depth = 0; depth < maxDepth; ++depth) {
        TTEntry* e = probeTT(board_.getHashKey());
        if (!e) break;

        Move m = e->bestMove;
        if (!isOnBoard(m)) break;

        if (!board_.makeMove(m.x, m.y)) {
            break; // illegal or already occupied
        }

        applied.push_back(m);
        outPV.push_back(m);
    }

    // Undo all applied moves.
    for (int i = static_cast<int>(applied.size()) - 1; i >= 0; --i) {
        const Move& m = applied[i];
        board_.unmakeMove(m.x, m.y);
    }
}

// =====================
// Iterative deepening
// =====================

void SearchEngine::iterativeDeepening() {
    lastResult_.principalVariation.clear();
    lastResult_.bestMove   = Move();
    lastResult_.bestScore  = 0;
    lastResult_.depthReached = 0;
    lastResult_.isMate     = false;
    lastResult_.isForcedWin = false;
    lastResult_.isTimeout  = false;

    // Simple iterative deepening with full-window PVS.
    for (int depth = 1; depth <= limits_.maxDepth; ++depth) {
        if (stop_) break;

        EvalScore score = search(depth,
                                 -kInfinity,
                                 +kInfinity,
                                 /*ply=*/0,
                                 /*allowNull=*/true,
                                 /*inPV=*/true);
        if (stop_) break;

        lastResult_.bestScore   = score;
        lastResult_.depthReached = depth;

        // Reconstruct PV and pick best move from it.
        extractPrincipalVariation(lastResult_.principalVariation, depth);
        if (!lastResult_.principalVariation.empty()) {
            lastResult_.bestMove = lastResult_.principalVariation.front();
        } else {
            // Fallback: pick any candidate move if PV is empty.
            auto moves = board_.getCandidateMoves();
            if (!moves.empty()) {
                lastResult_.bestMove = moves.front();
            }
        }

        // Mark mate scores.
        if (std::abs(score) >= kMateScore - 500) {
            lastResult_.isMate = true;
            break; // no need to search deeper
        }

        // Feed PV into history heuristic for ordering bias.
        if (history_ && !lastResult_.principalVariation.empty()) {
            Player p = rootSide_;
            for (std::size_t i = 0; i < lastResult_.principalVariation.size(); ++i) {
                int remainingDepth = depth - static_cast<int>(i);
                history_->recordPVMove(p, lastResult_.principalVariation[i],
                                       remainingDepth);
                p = opponent(p);
            }
        }

        // Update stats.
        lastResult_.nodes    = nodes_;
        lastResult_.qnodes   = qnodes_;
        lastResult_.hashHits = hashHits_;

        checkStopCondition();
        if (stop_) break;
    }
}

// =====================
// Public search API
// =====================

SearchResult SearchEngine::searchBestMove(const SearchLimits& limits) {
    limits_ = limits;
    nodes_    = 0;
    qnodes_   = 0;
    hashHits_ = 0;
    stop_     = false;
    startTime_ = Clock::now();

    rootSide_ = board_.sideToMove();

    // Optional: clear history heuristic between searches (policy choice).
    if (history_) {
        history_->clear();
    }

    lastResult_ = SearchResult();

    // Root-level threat solver: if it proves a forced win for the side to move
    // and the suggested first move is legal, we can immediately return it.
    if (threatSolver_) {
        ThreatAnalysis rootThreats =
            threatSolver_->analyzeThreats(board_, rootSide_);

        if (rootThreats.attackerHasForcedWin) {
            Move candidate = rootThreats.firstWinningMove;
            if (!rootThreats.winningLine.empty()) {
                candidate = rootThreats.winningLine.front();
            }

            if (isOnBoard(candidate) && !board_.isOccupied(candidate.x, candidate.y)) {
                lastResult_.bestMove  = candidate;
                lastResult_.bestScore = kMateScore - 1;
                lastResult_.depthReached = 0;
                lastResult_.isMate    = true;
                lastResult_.isForcedWin = true;

                if (!rootThreats.winningLine.empty()) {
                    lastResult_.principalVariation = rootThreats.winningLine;
                } else {
                    lastResult_.principalVariation.clear();
                    lastResult_.principalVariation.push_back(candidate);
                }

                lastResult_.nodes    = nodes_;
                lastResult_.qnodes   = qnodes_;
                lastResult_.hashHits = hashHits_;
                lastResult_.isTimeout = false;

                return lastResult_;
            }
        }
    }

    // Otherwise, run full PVS + iterative deepening.
    iterativeDeepening();

    lastResult_.nodes    = nodes_;
    lastResult_.qnodes   = qnodes_;
    lastResult_.hashHits = hashHits_;
    lastResult_.isTimeout = stop_;

    return lastResult_;
}

} // namespace gomoku