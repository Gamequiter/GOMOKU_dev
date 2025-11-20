// history_heuristic.h
// History heuristic for move ordering in the Gomoku search engine.
//
// This module maintains a history table that records how often a move at
// a particular board coordinate has been responsible for a cutoff during
// alpha–beta search.  Moves with larger history values are favoured in
// subsequent move orderings.  The table is reset at the start of each
// iterative deepening search.

#ifndef GOMOKU_HISTORY_HEURISTIC_H
#define GOMOKU_HISTORY_HEURISTIC_H

#include <cstring>
#include "board.h"

namespace gomoku {

// Simple history heuristic table keyed by board coordinates.
// The engine records how often a move causes a beta cutoff and uses
// that information to bias move ordering in later nodes.
class HistoryHeuristic {
public:
    HistoryHeuristic();

    // Reset the history table to zero for a new search.
    void reset();

    // Increment the history value for move m by depth^2.  Depth should
    // correspond to the remaining depth in the search tree when the cutoff
    // occurred; deeper cutoffs receive a larger increment.
    void increment(const Move &m, int depth);

    // Retrieve the history score for move m.
    int get(const Move &m) const;

private:
    // 12×12 table storing history scores for each board coordinate in
    // row-major order: table[y][x].
    int table[12][12];
};

} // namespace gomoku

#endif // GOMOKU_HISTORY_HEURISTIC_H