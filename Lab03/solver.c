#include <stdio.h>

#define N 9

extern void gop_show(int board[N][N]); // 假設 gop_show() 由外部提供

int is_valid(int board[N][N], int row, int col, int num) {
    for (int i = 0; i < N; i++) {
        if (board[row][i] == num || board[i][col] == num) {
            return 0;
        }
    }
    
    int startRow = (row / 3) * 3;
    int startCol = (col / 3) * 3;
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < 3; j++) {
            if (board[startRow + i][startCol + j] == num) {
                return 0;
            }
        }
    }
    return 1;
}

int solve_sudoku(int board[N][N]) {
    for (int row = 0; row < N; row++) {
        for (int col = 0; col < N; col++) {
            if (board[row][col] == 0) {
                for (int num = 1; num <= 9; num++) {
                    if (is_valid(board, row, col, num)) {
                        board[row][col] = num;
                        if (solve_sudoku(board)) {
                            return 1;
                        }
                        board[row][col] = 0;
                    }
                }
                return 0;
            }
        }
    }
    return 1;
}

int main() {
    int sudoku_board[N][N] = {
        {0, 0, 0, 0, 8, 2, 0, 0, 1},
        {0, 2, 0, 6, 1, 0, 0, 9, 8},
        {1, 0, 0, 0, 0, 5, 0, 0, 0},
        {5, 0, 6, 4, 9, 3, 0, 0, 7},
        {0, 3, 7, 0, 2, 8, 0, 4, 6},
        {8, 4, 2, 1, 7, 6, 0, 5, 0},
        {0, 0, 1, 8, 0, 0, 7, 6, 0},
        {0, 8, 0, 0, 0, 0, 0, 1, 3},
        {0, 0, 3, 2, 5, 1, 0, 0, 4}
    };

    if (solve_sudoku(sudoku_board)) {
        gop_show(sudoku_board);
    } else {
        printf("No solution exists\n");
    }
    return 0;
}
