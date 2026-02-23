import { useState } from 'react';
import { Upload, FileIcon } from 'lucide-react';

const FileUploadZone = ({ onFileUpload }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFileUpload(files[0]);
    }
  };

  const handleFileInput = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      onFileUpload(files[0]);
    }
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      className={`
        relative border-2 border-dashed rounded-lg p-12
        transition-all duration-300 ease-in-out cursor-pointer
        ${isDragging
          ? 'border-cyber-green bg-cyber-green/5 shadow-neon-green'
          : 'border-zinc-700 hover:border-zinc-600 bg-slate-900/50'
        }
      `}
    >
      <input
        type="file"
        id="file-upload"
        className="hidden"
        onChange={handleFileInput}
      />

      <label htmlFor="file-upload" className="cursor-pointer">
        <div className="flex flex-col items-center space-y-4">
          <div className={`
            p-6 rounded-full border-2 transition-all duration-300
            ${isDragging
              ? 'border-cyber-green bg-cyber-green/10'
              : 'border-zinc-700 bg-slate-800'
            }
          `}>
            <Upload
              className={`w-12 h-12 transition-colors duration-300 ${
                isDragging ? 'text-cyber-green' : 'text-slate-400'
              }`}
            />
          </div>

          <div className="text-center">
            <h3 className="text-xl font-semibold text-slate-200 mb-2">
              Drop File to Analyze
            </h3>
            <p className="text-sm text-slate-400">
              or click to browse your files
            </p>
            <p className="text-xs text-slate-500 mt-3">
              Supported: Images, Documents, Archives (Max 50MB)
            </p>
          </div>

          <div className="flex items-center space-x-2 text-xs text-slate-500">
            <FileIcon className="w-4 h-4" />
            <span>Ready for forensic analysis</span>
          </div>
        </div>
      </label>
    </div>
  );
};

export default FileUploadZone;
