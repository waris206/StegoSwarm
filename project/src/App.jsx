import { useState } from 'react';
import Navbar from './components/Navbar';
import FileUploadZone from './components/FileUploadZone';
import FileDetailsCard from './components/FileDetailsCard';
import LiveTerminal from './components/LiveTerminal';
import InvestigationTimeline from './components/InvestigationTimeline';

function App() {
  const [uploadedFile, setUploadedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStage, setCurrentStage] = useState(null);

  const handleFileUpload = async (file) => {
    setIsAnalyzing(true);
    setCurrentStage('upload');

    const formData = new FormData();
    formData.append('file', file);

    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
      const response = await fetch(`${apiUrl}/upload`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      if (data.success && data.file) {
        // Capture sha256, entropy, magic bytes, and VirusTotal stats from backend response
        setUploadedFile({
          name: data.file.name,
          size: data.file.size,
          sha256: data.file.sha256,
          entropy: data.file.entropy,
          magicBytes: data.file.magicBytes,
          virusTotal: data.file.virusTotal,
        });

        setTimeout(() => setCurrentStage('hashed'), 500);
        setTimeout(() => setCurrentStage('metadata'), 2000);
        setTimeout(() => setCurrentStage('stego'), 3500);
        setTimeout(() => {
          setCurrentStage('report');
          setIsAnalyzing(false);
        }, 5500);
      } else {
        throw new Error('Upload response missing success or file data');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      setIsAnalyzing(false);
      setCurrentStage(null);
      alert(`Upload failed: ${error.message}`);
    }
  };

  const handleReset = () => {
    setUploadedFile(null);
    setIsAnalyzing(false);
    setCurrentStage(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Navbar />

      <main className="flex-1 container mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-2 space-y-6">
            {!uploadedFile ? (
              <FileUploadZone onFileUpload={handleFileUpload} />
            ) : (
              <div className="space-y-4">
                <FileDetailsCard file={uploadedFile} />
                <button
                  onClick={handleReset}
                  className="w-full px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-zinc-700 transition-colors text-sm"
                >
                  Analyze Another File
                </button>
              </div>
            )}
          </div>

          <div className="lg:col-span-1">
            <LiveTerminal
              isActive={isAnalyzing}
              fileId={uploadedFile?.sha256}
            />
          </div>
        </div>

        <InvestigationTimeline currentStage={currentStage} />
      </main>

      <footer className="border-t border-zinc-800 bg-slate-900 px-6 py-4">
        <div className="container mx-auto flex items-center justify-between text-xs text-slate-500">
          <div>
            StegoSwarm v1.0.0 - Digital Forensics Platform
          </div>
          <div className="flex items-center space-x-4">
            <span>5 AI Agents Active</span>
            <span>•</span>
            <span>Quantum-Grade Analysis</span>
          </div>
        </div>
      </footer>
    </div>
  );
}

export default App;
