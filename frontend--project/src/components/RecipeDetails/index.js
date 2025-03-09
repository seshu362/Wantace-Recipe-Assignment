import React, { useState, useEffect } from "react";
import { useParams, useNavigate } from "react-router-dom";
import "./index.css";

const RecipeDetails = () => {
  const { id } = useParams(); // Get the recipe ID from the URL
  const navigate = useNavigate();
  const [recipe, setRecipe] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch the recipe data when the component mounts
  useEffect(() => {
    const fetchRecipe = async () => {
      try {
        const token = localStorage.getItem("token");
        const response = await fetch(`https://wantace-assignment-backend.onrender.com/recipes/${id}`, {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        });

        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.error || "Failed to fetch recipe");
        }

        const data = await response.json();
        setRecipe(data);
      } catch (err) {
        console.error("Fetch recipe error:", err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchRecipe();
  }, [id]);

  if (loading) return <div>Loading...</div>;
  if (error) return <div>Error: {error}</div>;
  if (!recipe) return <div>Recipe not found</div>;

  return (
    <div className="recipe-details">
      <button className="back-button" onClick={() => navigate("/")}>
        &larr; Back to Home
      </button>
      <h1>{recipe.title}</h1>
      <img src={recipe.imageUrl} alt={recipe.title} />
      <p>{recipe.description}</p>
      <h3>Ingredients</h3>
      <p>{recipe.ingredients}</p>
      <h3>Instructions</h3>
      <p>{recipe.instructions}</p>
      <button
        className="edit-recipe-button"
        onClick={() => navigate(`/recipe/${id}/edit`)}
      >
        Edit Recipe
      </button>
    </div>
  );
};

export default RecipeDetails;