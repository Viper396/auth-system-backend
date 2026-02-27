import React, { createContext, useState, useContext, useEffect } from "react";
import { authAPI } from "../services/api";
import {
  setAuthToken,
  clearAuthToken,
  getTokenData,
} from "../utils/authHelper";

const AuthContext = createContext();

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize auth state
  useEffect(() => {
    const initAuth = async () => {
      const token = localStorage.getItem("accessToken");
      if (token) {
        const tokenData = getTokenData();
        if (tokenData) {
          // Fetch user profile to get complete data
          try {
            const { data } = await authAPI.refresh();
            setAuthToken(data.accessToken);
            setUser(data.user);
          } catch (error) {
            clearAuthToken();
          }
        }
      }
      setLoading(false);
    };

    initAuth();
  }, []);

  const signup = async (email, password) => {
    const { data } = await authAPI.signup({ email, password });
    return data;
  };

  const login = async (email, password) => {
    const { data } = await authAPI.login({ email, password });
    setAuthToken(data.accessToken);
    setUser(data.user);
    return data;
  };

  const logout = async () => {
    try {
      await authAPI.logout();
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      clearAuthToken();
      setUser(null);
    }
  };

  const updateUser = (userData) => {
    setUser((prev) => ({ ...prev, ...userData }));
  };

  const value = {
    user,
    loading,
    signup,
    login,
    logout,
    updateUser,
    isAuthenticated: !!user,
    isAdmin: user?.role === "admin",
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};
