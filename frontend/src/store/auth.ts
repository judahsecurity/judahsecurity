import { create } from 'zustand';
import { api } from '@/lib/api';

interface User {
  id: number;
  email: string;
  full_name: string;
  role: string;
  is_active: boolean;
  must_change_password?: boolean;
}

interface AuthState {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string, captchaToken?: string) => Promise<void>;
  logout: () => Promise<void>;
  checkAuth: () => Promise<void>;
}

export const useAuth = create<AuthState>((set) => ({
  user: null,
  isLoading: true,
  isAuthenticated: false,

  login: async (email: string, password: string, captchaToken?: string) => {
    set({ isLoading: true });
    try {
      await api.login(email, password, captchaToken);
      const user = await api.getCurrentUser();
      set({ user, isAuthenticated: true, isLoading: false });
    } catch (error) {
      set({ isLoading: false });
      throw error;
    }
  },

  logout: async () => {
    set({ isLoading: true });
    try {
      await api.logout();
    } finally {
      set({ user: null, isAuthenticated: false, isLoading: false });
    }
  },

  checkAuth: async () => {
    set({ isLoading: true });
    try {
      if (!api.getToken() && !api.hasRefreshToken()) {
        set({ user: null, isAuthenticated: false, isLoading: false });
        return;
      }
      const user = await api.getCurrentUser();
      set({ user, isAuthenticated: true, isLoading: false });
    } catch (error: any) {
      const status = error?.response?.status;
      if (status === 401) {
        api.clearSession();
        set({ user: null, isAuthenticated: false, isLoading: false });
        return;
      }
      // Backend blip / 5xx / network: keep tokens so a refresh does not log the user out.
      set({
        isAuthenticated: Boolean(api.getToken() || api.hasRefreshToken()),
        isLoading: false,
      });
    }
  },
}));














