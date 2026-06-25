import { useState, useCallback, useEffect } from 'react';
import type { GameState, LeaderboardEntry, ShotResult, GameConfig } from '../types/game';

const STORAGE_KEY = 'stucred_football_game';
const LEADERBOARD_KEY = 'stucred_football_leaderboard';

const DEFAULT_CONFIG: GameConfig = {
  duration: 30,
  maxShots: 10,
  goalkeeperSpeed: 1,
  targetSize: 60,
};

const DEMO_NAMES = ['Rahul', 'Priya', 'Amit', 'Sneha', 'Vikram', 'Ananya', 'Karthik', 'Divya'];

function loadState(): Partial<GameState> {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved) return JSON.parse(saved);
  } catch { /* ignore */ }
  return {};
}

function loadLeaderboard(): LeaderboardEntry[] {
  try {
    const saved = localStorage.getItem(LEADERBOARD_KEY);
    if (saved) {
      const entries = JSON.parse(saved);
      // Check if we need to reset (new day)
      const lastReset = entries.length > 0 ? entries[0]?.date : null;
      const today = new Date().toISOString().split('T')[0];
      if (lastReset !== today) {
        // Generate new demo entries for the new day
        return generateDemoLeaderboard();
      }
      return entries;
    }
  } catch { /* ignore */ }
  return generateDemoLeaderboard();
}

function generateDemoLeaderboard(): LeaderboardEntry[] {
  const today = new Date().toISOString().split('T')[0];
  const entries: LeaderboardEntry[] = [];
  const usedNames = new Set<string>();
  
  for (let i = 0; i < 8; i++) {
    let name: string;
    do {
      name = DEMO_NAMES[Math.floor(Math.random() * DEMO_NAMES.length)];
    } while (usedNames.has(name));
    usedNames.add(name);
    
    entries.push({
      rank: i + 1,
      name,
      score: Math.floor(Math.random() * 500) + 200 - (i * 40),
      date: today,
    });
  }
  
  return entries.sort((a, b) => b.score - a.score).map((e, i) => ({ ...e, rank: i + 1 }));
}

function saveState(state: Partial<GameState>) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  } catch { /* ignore */ }
}

function saveLeaderboard(entries: LeaderboardEntry[]) {
  try {
    localStorage.setItem(LEADERBOARD_KEY, JSON.stringify(entries));
  } catch { /* ignore */ }
}

export function useGameState() {
  const saved = loadState();
  const [gameState, setGameState] = useState<GameState>({
    screen: 'menu',
    score: 0,
    highScore: saved.highScore || 0,
    shotsTaken: 0,
    shotsMade: 0,
    currentStreak: 0,
    bestStreak: saved.bestStreak || 0,
    totalGamesPlayed: saved.totalGamesPlayed || 0,
    dailyLeaderboard: loadLeaderboard(),
    lastResetDate: new Date().toISOString().split('T')[0],
    ...saved,
  });

  const [gameConfig] = useState<GameConfig>(DEFAULT_CONFIG);
  const [timeRemaining, setTimeRemaining] = useState(30);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    saveState({
      highScore: gameState.highScore,
      bestStreak: gameState.bestStreak,
      totalGamesPlayed: gameState.totalGamesPlayed,
    });
  }, [gameState.highScore, gameState.bestStreak, gameState.totalGamesPlayed]);

  useEffect(() => {
    saveLeaderboard(gameState.dailyLeaderboard);
  }, [gameState.dailyLeaderboard]);

  const startGame = useCallback(() => {
    setGameState(prev => ({
      ...prev,
      screen: 'game',
      score: 0,
      shotsTaken: 0,
      shotsMade: 0,
      currentStreak: 0,
    }));
    setTimeRemaining(gameConfig.duration);
    setIsPlaying(true);
  }, [gameConfig.duration]);

  const endGame = useCallback((finalScore: number) => {
    setIsPlaying(false);
    
    setGameState(prev => {
      const newTotalGames = prev.totalGamesPlayed + 1;
      const newHighScore = Math.max(prev.highScore, finalScore);
      
      // Add to leaderboard if score is good enough
      const today = new Date().toISOString().split('T')[0];
      const newEntry: LeaderboardEntry = {
        rank: 0,
        name: 'You',
        score: finalScore,
        date: today,
      };
      
      const updatedLeaderboard = [...prev.dailyLeaderboard, newEntry]
        .sort((a, b) => b.score - a.score)
        .slice(0, 10)
        .map((e, i) => ({ ...e, rank: i + 1 }));
      
      return {
        ...prev,
        screen: 'result',
        score: finalScore,
        highScore: newHighScore,
        totalGamesPlayed: newTotalGames,
        dailyLeaderboard: updatedLeaderboard,
      };
    });
  }, []);

  const processShot = useCallback((result: ShotResult) => {
    setGameState(prev => {
      const newStreak = result.made ? prev.currentStreak + 1 : 0;
      const newBestStreak = Math.max(prev.bestStreak, newStreak);
      const streakBonus = newStreak >= 3 ? newStreak * 10 : 0;
      const points = result.points + streakBonus;
      
      return {
        ...prev,
        score: prev.score + points,
        shotsTaken: prev.shotsTaken + 1,
        shotsMade: result.made ? prev.shotsMade + 1 : prev.shotsMade,
        currentStreak: newStreak,
        bestStreak: newBestStreak,
      };
    });
  }, []);

  const setScreen = useCallback((screen: GameState['screen']) => {
    setGameState(prev => ({ ...prev, screen }));
  }, []);

  return {
    gameState,
    gameConfig,
    timeRemaining,
    isPlaying,
    startGame,
    endGame,
    processShot,
    setScreen,
    setTimeRemaining,
    setIsPlaying,
  };
}
