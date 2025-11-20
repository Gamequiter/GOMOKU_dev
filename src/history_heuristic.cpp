// history_heuristic.cpp
// Implementation of HistoryHeuristic for Gomoku search engine.

#include "history_heuristic.h"

namespace gomoku {

HistoryHeuristic::HistoryHeuristic() {
    reset();
}

void HistoryHeuristic::reset() {
    // Zero out the history table.
    std::memset(table, 0, sizeof(table));
}

void HistoryHeuristic::increment(const Move &m, int depth) {
    // Only update the table for moves that fall on the board.
    if (m.x >= 0 && m.x < 12 && m.y >= 0 && m.y < 12) {
        // Increment by depth squared so deeper cutoffs contribute more.
        int bonus = depth * depth;
        // Use row-major indexing: first index is y (row), second is x (column).
        table[m.y][m.x] += bonus;
    }
}

int HistoryHeuristic::get(const Move &m) const {
    if (m.x >= 0 && m.x < 12 && m.y >= 0 && m.y < 12) {
        // Use the same row-major indexing as in increment().
        return table[m.y][m.x];
    }
    return 0;
}

} // namespace gomoku