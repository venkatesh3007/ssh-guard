export interface GameState {
  screen: 'menu' | 'game' | 'result' | 'leaderboard';
  score: number;
  highScore: number;
  shotsTaken: number;
  shotsMade: number;
  currentStreak: number;
  bestStreak: number;
  totalGamesPlayed: number;
  dailyLeaderboard: LeaderboardEntry[];
  lastResetDate: string;
}

export interface LeaderboardEntry {
  rank: number;
  name: string;
  score: number;
  date: string;
}

export interface ShotResult {
  made: boolean;
  points: number;
  multiplier: number;
  message: string;
}

export type Difficulty = 'easy' | 'medium' | 'hard';

export interface GameConfig {
  duration: number;
  maxShots: number;
  goalkeeperSpeed: number;
  targetSize: number;
}
