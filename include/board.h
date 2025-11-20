// board.h
// Gomoku board representation using bitboards.

#ifndef GOMOKU_BOARD_H
#define GOMOKU_BOARD_H

#include <cstdint>
#include <vector>

namespace gomoku {

// Representation of the two possible players.
enum class Player {
    Black = 0,
    White = 1
};

// Simple struct to hold a move coordinate.
struct Move {
    int x;
    int y;
    Move(int px = 0, int py = 0) : x(px), y(py) {}

    // Order by (x,y) so we can sort
    bool operator<(const Move& other) const {
        if (x != other.x) return x < other.x;
        return y < other.y;
    }

    bool operator==(const Move& other) const {
        return x == other.x && y == other.y;
    }
};

// Represents a 12×12 Gomoku board using bitboards.
class Board {
public:
    // Construct a fresh board with the predetermined opening stones.
    Board();

    // Return true if the cell at (x,y) is occupied by any stone.
    bool isOccupied(int x, int y) const;

     // Returns the player whose turn it is to move.
    Player sideToMove() const { return side_to_move; }

    // Attempt to place a stone at (x,y) for the current player.
    // Returns false if the move was illegal (cell already occupied).
    bool makeMove(int x, int y);

    // Undo the last move at (x,y).  This will revert side_to_move to the
    // player who originally played at (x,y) and clear the stone at that
    // location.  It assumes that the cell currently contains a stone of
    // the opponent of side_to_move (i.e., the last move made).  Always
    // returns true.
    bool unmakeMove(int x, int y);

    // Check whether the specified player currently has five in a row.
    bool checkWin(Player player) const;

    // Get a list of legal (empty) positions on the board.
    std::vector<Move> getLegalMoves() const;

    // Generate candidate moves within a bounding box around existing stones.
    // This function is intended for use by the search engine.  It limits
    // move generation to locations close to the action (within a margin of
    // two cells of any existing stone) and ignores cells that have no
    // neighboring stones.  If the board is empty (no stones), it will
    // return the central location (5,5) as the only candidate.
    std::vector<Move> getCandidateMoves() const;

    // Return a code describing the occupant of the cell at (x,y):
    // 0 = empty, 1 = black, 2 = white.  This helper is mainly for
    // evaluation purposes.
    int getCellState(int x, int y) const;

    // Utility to count how many stones a player has on the board.
    int countStones(Player player) const;

    // Return the Zobrist hash key for the current position.  This value
    // uniquely represents the state of the board (including side to move) and
    // can be used by transposition tables.  It is updated incrementally as
    // moves are made and undone, and remains consistent after any public
    // mutator that changes the board contents or side to move
    // (makeMove, unmakeMove, placeStone, removeStone, setSideToMove).
    uint64_t getHashKey() const { return hashKey; }

    //Helper functions:
    Player getSideToMove() const;//Inspect current side (legacy alias; prefer sideToMove() in new code)
    void setSideToMove(Player p);//Force a specific side to move; maintains the Zobrist hash key
    bool placeStone(int x, int y, Player player);//Place a stone for a specific Player without toggling turn; maintains the Zobrist hash key
    bool removeStone(int x, int y, Player player);//Place a stone for a specific Player without toggling turn; maintains the Zobrist hash key

private:
    // Convert a pair (x,y) into an index 0..143.
    static inline int index(int x, int y) { return y * 12 + x; }

    // Convert index into chunk 0..2 and bit offset 0..63.
    static inline int chunkOf(int idx) { return idx >> 6; }
    static inline int offsetOf(int idx) { return idx & 63; }

    // Bitboards for black and white. bb[player][chunk] holds bits for that player.
    uint64_t bb[2][3];

    // The player who will make the next move.
    Player side_to_move;

    // --- Zobrist hashing support ---
    // Static tables storing random 64‑bit numbers for each board cell and player.
    // These are initialized on first construction of a Board via initZobrist().
    static bool zobristInitialized;
    static uint64_t zobristTable[12][12][2];
    static uint64_t zobristSide;

    // The current position's Zobrist hash key.  It is maintained
    // incrementally and remains consistent after all public mutators that
    // change the board contents or side to move (makeMove, unmakeMove,
    // placeStone, removeStone, setSideToMove).
    uint64_t hashKey;

    // Initialize Zobrist tables with random numbers.  Called lazily by the
    // constructor to ensure proper seeding.
    static void initZobrist();
};

} // namespace gomoku

#endif // GOMOKU_BOARD_H