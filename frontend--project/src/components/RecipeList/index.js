import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import "./index.css";

const RecipeList = () => {
  const [recipes, setRecipes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchRecipes = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch("https://wantace-assignment-backend.onrender.com/recipes", {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || "Failed to fetch recipes");
        }

        const data = await response.json();
        setRecipes(data);
      } catch (err) {
        console.error("Fetch recipes error:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchRecipes();
  }, []);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;

  return (
    <div className="recipe-list">
      <h1>Recipes</h1>
      <Link to="/submit" className="add-recipe-button">
        Add New Recipe
      </Link>
      <ul>
        {recipes.map((recipe) => (
          <li key={recipe.id} className="recipe-item">
            <Link to={`/recipe/${recipe.id}`}>
              <h2>{recipe.title}</h2>
              <p>{recipe.description}</p>
            </Link>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default RecipeList;