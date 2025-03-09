import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { FontAwesomeIcon } from "@fortawesome/react-fontawesome";
import { faEye, faEyeSlash } from "@fortawesome/free-solid-svg-icons";
import "./index.css";

const Signup = () => {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false); // State to toggle password visibility
  const [error, setError] = useState(null); // For general errors
  const [validationErrors, setValidationErrors] = useState([]); // For validation errors
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null); // Clear previous errors
    setValidationErrors([]); // Clear previous validation errors

    try {
      const response = await fetch("https://wantace-assignment-backend.onrender.com/signup", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ name, email, password }),
      });

      if (!response.ok) {
        const errorData = await response.json();

        // Handle validation errors
        if (errorData.errors) {
          setValidationErrors(errorData.errors);
        } else {
          throw new Error(errorData.error || "Failed to sign up");
        }
        return;
      }

      const data = await response.json();
      localStorage.setItem("token", data.token); // Save token to localStorage
      navigate("/"); // Redirect to home page
    } catch (err) {
      console.error("Signup error:", err);
      setError(err.message);
    }
  };

  return (
    <div className="auth-form">
      <h1>Signup</h1>
      {error && <div className="error">{error}</div>}
      {validationErrors.length > 0 && (
        <div className="validation-errors">
          {validationErrors.map((err, index) => (
            <div key={index} className="error">
              {err.msg}
            </div>
          ))}
        </div>
      )}
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Name"
          value={name}
          onChange={(e) => setName(e.target.value)}
          required
        />
        <input
          type="email"
          placeholder="Email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <div className="password-input-container">
          <input
            type={showPassword ? "text" : "password"} // Toggle input type
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
          />
          <span
            className="toggle-password-icon"
            onClick={() => setShowPassword(!showPassword)}
          >
            <FontAwesomeIcon icon={showPassword ? faEyeSlash : faEye} />
          </span>
        </div>
        <button type="submit">Signup</button>
      </form>
      <p>
        Already have an account?{" "}
        <button onClick={() => navigate("/login")}>Login</button>
      </p>
    </div>
  );
};

export default Signup;