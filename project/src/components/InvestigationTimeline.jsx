import { Upload, Hash, FileSearch, Shield, FileCheck, Check } from 'lucide-react';

const InvestigationTimeline = ({ currentStage }) => {
  const stages = [
    { id: 'upload', label: 'Uploaded', icon: Upload },
    { id: 'hashed', label: 'Hashed', icon: Hash },
    { id: 'metadata', label: 'Metadata Analyzed', icon: FileSearch },
    { id: 'stego', label: 'Stego Checked', icon: Shield },
    { id: 'report', label: 'Report Generated', icon: FileCheck },
  ];

  const getStageIndex = (stageId) => {
    return stages.findIndex(s => s.id === stageId);
  };

  const currentIndex = getStageIndex(currentStage);

  return (
    <div className="bg-slate-900 border border-zinc-800 rounded-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center space-x-2">
          <FileCheck className="w-4 h-4 text-cyber-blue" />
          <span>Investigation Timeline</span>
        </h3>
        {currentStage && (
          <span className="text-xs text-slate-500">
            Stage {currentIndex + 1} of {stages.length}
          </span>
        )}
      </div>

      <div className="relative">
        <div className="absolute top-6 left-0 right-0 h-0.5 bg-zinc-800"></div>
        <div
          className="absolute top-6 left-0 h-0.5 bg-cyber-green transition-all duration-500"
          style={{
            width: currentStage ? `${(currentIndex / (stages.length - 1)) * 100}%` : '0%'
          }}
        ></div>

        <div className="relative flex justify-between">
          {stages.map((stage, index) => {
            const isCompleted = index <= currentIndex;
            const isCurrent = index === currentIndex;
            const Icon = stage.icon;

            return (
              <div key={stage.id} className="flex flex-col items-center">
                <div
                  className={`
                    w-12 h-12 rounded-full border-2 flex items-center justify-center
                    transition-all duration-300 relative z-10
                    ${isCompleted
                      ? 'bg-cyber-green/20 border-cyber-green'
                      : 'bg-slate-900 border-zinc-700'
                    }
                    ${isCurrent ? 'shadow-neon-green' : ''}
                  `}
                >
                  {isCompleted && index < currentIndex ? (
                    <Check className="w-5 h-5 text-cyber-green" />
                  ) : (
                    <Icon
                      className={`w-5 h-5 ${
                        isCompleted ? 'text-cyber-green' : 'text-slate-600'
                      }`}
                    />
                  )}
                </div>
                <span
                  className={`
                    mt-3 text-xs text-center max-w-[80px]
                    ${isCompleted ? 'text-slate-300 font-medium' : 'text-slate-600'}
                  `}
                >
                  {stage.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {!currentStage && (
        <div className="mt-6 text-center text-xs text-slate-600">
          Upload a file to begin investigation
        </div>
      )}
    </div>
  );
};

export default InvestigationTimeline;
