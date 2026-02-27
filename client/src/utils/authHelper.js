import { jwtDecode } from "jwt-decode";

export const getTokenData = () => {
  const token = localStorage.getItem("accessToken");
  if (!token) return null;

  try {
    const decoded = jwtDecode(token);
    return decoded;
  } catch (error) {
    return null;
  }
};

export const isTokenExpired = () => {
  const token = localStorage.getItem("accessToken");
  if (!token) return true;

  try {
    const decoded = jwtDecode(token);
    return decoded.exp * 1000 < Date.now();
  } catch (error) {
    return true;
  }
};

export const setAuthToken = (token) => {
  localStorage.setItem("accessToken", token);
};

export const clearAuthToken = () => {
  localStorage.removeItem("accessToken");
};
