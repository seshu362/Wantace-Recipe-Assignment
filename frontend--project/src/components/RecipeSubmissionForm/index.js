import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import "./index.css";

const RecipeSubmissionForm = () => {
  const [formData, setFormData] = useState({
    title: "",
    description: "",
    ingredients: "",
    instructions: "",
    imageUrl: "",
    categoryId: "",
  });
  const [file, setFile] = useState(null);
  const [useImageUrl, setUseImageUrl] = useState(false); // Toggle between URL and file upload
  const [error, setError] = useState(null);
  const navigate = useNavigate();

  const handleChange = (e) => {
    const { name, value } = e.target;
    setFormData({ ...formData, [name]: value });
  };

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
  };

  const handleToggle = () => {
    setUseImageUrl(!useImageUrl); // Toggle between URL and file upload
    setFile(null); // Reset file if switching to URL
    setFormData({ ...formData, imageUrl: "" }); // Reset URL if switching to file
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem("token");

      let imageUrl = formData.imageUrl; // Default to the provided URL

      // If the user uploaded a file, upload it and get the URL
      if (!useImageUrl && file) {
        const formData = new FormData();
        formData.append("image", file);

        const uploadResponse = await fetch("http://localhost:5000/upload", {
          method: "POST",
          body: formData,
        });

        if (!uploadResponse.ok) {
          throw new Error("Failed to upload image");
        }

        const uploadData = await uploadResponse.json();
        imageUrl = uploadData.imageUrl;
      }

      // Submit the recipe with the image URL
      const recipeData = {
        ...formData,
        imageUrl: imageUrl,
      };

      const response = await fetch("https://wantace-assignment-backend.onrender.com/recipes", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(recipeData),
      });

      if (!response.ok) {
        throw new Error("Failed to submit recipe");
      }

      navigate("/");
    } catch (err) {
      setError(err.message);
    }
  };

  return (
    <div className="recipe-form">
      <button className="back-button" onClick={() => navigate("/")}>
        &larr; Back to Home
      </button>
      <h1>Submit a New Recipe</h1>
      {error && <div className="error">{error}</div>}
      <form onSubmit={handleSubmit}>
        <label>Title</label>
        <input
          type="text"
          name="title"
          value={formData.title}
          onChange={handleChange}
          required
        />
        <label>Description</label>
        <textarea
          name="description"
          value={formData.description}
          onChange={handleChange}
          required
        />
        <label>Ingredients</label>
        <textarea
          name="ingredients"
          value={formData.ingredients}
          onChange={handleChange}
          required
        />
        <label>Instructions</label>
        <textarea
          name="instructions"
          value={formData.instructions}
          onChange={handleChange}
          required
        />
        <label>Category ID</label>
        <input
          type="text"
          name="categoryId"
          value={formData.categoryId}
          onChange={handleChange}
        />
        <div className="image-upload-option">
          <label>
            <input
              type="checkbox"
              checked={useImageUrl}
              onChange={handleToggle}
            />
            Use Image URL
          </label>
        </div>
        {useImageUrl ? (
          <>
            <label>Image URL</label>
            <input
              type="text"
              name="imageUrl"
              value={formData.imageUrl}
              onChange={handleChange}
            />
          </>
        ) : (
          <>
            <label>Upload Image</label>
            <input
              type="file"
              name="image"
              onChange={handleFileChange}
            />
          </>
        )}
        <button type="submit">Submit</button>
      </form>
    </div>
  );
};

export default RecipeSubmissionForm;