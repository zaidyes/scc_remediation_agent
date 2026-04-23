import React, { useState } from 'react';

const ConfigWizard = () => {
  const [currentStep, setCurrentStep] = useState(1);
  const [dryRun, setDryRun] = useState(true);

  const steps = [
    { num: 1, title: 'Scope' },
    { num: 2, title: 'Severity & Filters' },
    { num: 3, title: 'Approval Policy' },
    { num: 4, title: 'Execution' },
    { num: 5, title: 'Notifications' },
  ];

  return (
    <div className="wizard-container p-6 max-w-4xl mx-auto">
      {dryRun && (
        <div className="bg-yellow-100 border-l-4 border-yellow-500 text-yellow-700 p-4 mb-6">
          <p className="font-bold">Dry-run mode active</p>
          <p>The agent generates plans but will not execute any changes.</p>
        </div>
      )}

      <div className="flex mb-8">
        {steps.map(step => (
          <div key={step.num} className="flex-1 text-center">
            <div className={`w-8 h-8 mx-auto rounded-full flex items-center justify-center ${currentStep === step.num ? 'bg-blue-600 text-white' : 'bg-gray-200 text-gray-600'}`}>
              {step.num}
            </div>
            <div className="mt-2 text-sm">{step.title}</div>
          </div>
        ))}
      </div>

      <div className="card bg-white shadow-md rounded-lg p-6">
        <h2 className="text-2xl font-bold mb-4">{steps[currentStep-1].title}</h2>
        {/* Step content would go here */}
        <p className="mb-6 text-gray-600">Configure settings for {steps[currentStep-1].title.toLowerCase()}...</p>

        <div className="flex justify-between mt-8">
          <button 
            className="px-4 py-2 bg-gray-200 rounded disabled:opacity-50"
            disabled={currentStep === 1}
            onClick={() => setCurrentStep(prev => prev - 1)}
          >
            Back
          </button>
          
          {currentStep < 5 ? (
            <button 
              className="px-4 py-2 bg-blue-600 text-white rounded"
              onClick={() => setCurrentStep(prev => prev + 1)}
            >
              Save & Continue
            </button>
          ) : (
            <button className="px-4 py-2 bg-green-600 text-white rounded">
              Activate Agent
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default ConfigWizard;
