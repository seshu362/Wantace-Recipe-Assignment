import React, { useEffect, useState } from "react";
import { Routes, Route, useNavigate, Navigate, useLocation } from "react-router-dom";
import RecipeList from "./components/RecipeList";
import RecipeDetails from "./components/RecipeDetails";
import RecipeSubmissionForm from "./components/RecipeSubmissionForm";
import RecipeEditForm from "./components/RecipeEditForm";
import Login from "./components/Auth/Login";
import Signup from "./components/Auth/Signup";
import "./App.css";

function App() {
  const [theme, setTheme] = useState("light");
  const navigate = useNavigate();
  const location = useLocation(); // Get the current route location

  // Check if the user is authenticated
  const isAuthenticated = !!localStorage.getItem("token");

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isAuthenticated && location.pathname !== "/login" && location.pathname !== "/signup") {
      navigate("/login");
    }
  }, [isAuthenticated, navigate, location]);

  const toggleTheme = () => {
    setTheme(theme === "light" ? "dark" : "light");
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/login");
  };

  // Hide logout button on login and signup pages
  const showLogoutButton = !["/login", "/signup"].includes(location.pathname);

  return (
    <div className={`App ${theme}`} data-theme={theme}>
      <button onClick={toggleTheme} className="theme-toggle">
        {theme === "light" ? "🌙" : "☀️"}
      </button>
      {showLogoutButton && (
        <button onClick={handleLogout} className="logout-button">
          Logout
        </button>
      )}
      <Routes>
        <Route
          path="/"
          element={isAuthenticated ? <RecipeList /> : <Navigate to="/login" />}
        />
        <Route
          path="/recipe/:id"
          element={isAuthenticated ? <RecipeDetails /> : <Navigate to="/login" />}
        />
        <Route
          path="/submit"
          element={isAuthenticated ? <RecipeSubmissionForm /> : <Navigate to="/login" />}
        />
        <Route
          path="/recipe/:id/edit"
          element={isAuthenticated ? <RecipeEditForm /> : <Navigate to="/login" />}
        />
        <Route path="/login" element={<Login />} />
        <Route path="/signup" element={<Signup />} />
      </Routes>
    </div>
  );
}

export default App;