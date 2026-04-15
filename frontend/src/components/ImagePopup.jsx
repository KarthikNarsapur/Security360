import React, { useState } from "react";
import { ImCross } from "react-icons/im";
import { FaCloudUploadAlt } from "react-icons/fa";

const ImagePopup = ({ imageSrc, onClose, onImageChange }) => {
  const [dragActive, setDragActive] = useState(false);

  const handleDrag = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(e.type === "dragenter" || e.type === "dragover");
  };

  const handleDrop = (e) => {
    e.preventDefault();
    e.stopPropagation();
    setDragActive(false);
    
    if (e.dataTransfer.files?.[0]) {
      onImageChange(e.dataTransfer.files[0]);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex justify-center items-center z-50">
      <div className="bg-white dark:bg-gray-700 rounded-lg p-6 w-96 relative">
        <button className="absolute top-2 right-2 text-gray-600 dark:text-gray-400" onClick={onClose}>
          <ImCross />
        </button>
        <h2 className="text-lg font-semibold mb-4 text-gray-800 dark:text-white">Update Profile Picture</h2>
        
        <div
          className={`border-2 border-dashed rounded-lg p-4 text-center transition-all duration-300 ${
            dragActive 
              ? 'border-blue-500 bg-blue-50 dark:bg-gray-700' 
              : 'border-gray-300 dark:border-gray-600'
          }`}
          onDragEnter={handleDrag}
          onDragLeave={handleDrag}
          onDragOver={handleDrag}
          onDrop={handleDrop}
        >
          <img
            src={imageSrc}
            alt="Current"
            className="w-32 h-32 mx-auto rounded-full object-cover mb-4"
          />
          <FaCloudUploadAlt className="w-12 h-12 mx-auto text-gray-400" />
          <p className="text-gray-600 dark:text-gray-300 mt-2">
            Drag & drop your image here
          </p>
          <p className="text-sm text-gray-500 dark:text-gray-400 my-2">or</p>
          <label className="block px-4 py-2 bg-indigo-700 text-white border-indigo-700 font-semibold hover:!bg-indigo-500 hover:!font-semibold hover:!text-white hover:!border-indigo-500 dark:bg-gray-500 dark:border-gray-500 dark:hover:!bg-gray-400 dark:hover:!border-gray-400 rounded-lg cursor-pointer transition-colors">
            Choose File
            <input
              type="file"
              className="hidden"
              accept="image/*"
              onChange={(e) => onImageChange(e.target.files[0])}
            />
          </label>
        </div>
      </div>
    </div>
  );
};

export default ImagePopup;