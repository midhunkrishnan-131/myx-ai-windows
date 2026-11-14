import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertOctagon, RotateCcw } from 'lucide-react';
import { Button } from '../ui/Button';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  };

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
    console.error('[MYX ErrorBoundary caught render error]:', error, errorInfo);
  }

  public handleReset = () => {
    this.setState({ hasError: false, error: null });
  };

  public render() {
    if (this.state.hasError) {
      return (
        <div className="p-6 my-4 bg-[#141920] border border-[#EF4444]/40 rounded-xl space-y-4">
          <div className="flex items-center gap-3 text-[#EF4444]">
            <AlertOctagon className="w-6 h-6 shrink-0" />
            <h2 className="text-base font-bold text-[#F5F7FA]">
              {this.props.fallbackTitle || 'Security Module Rendering Error'}
            </h2>
          </div>
          <p className="text-xs text-[#A7B0BC] leading-relaxed">
            An unexpected error occurred while rendering this module. You can attempt to recover
            the module or reload the page.
          </p>
          {this.state.error && (
            <pre className="p-3 bg-[#080A0D] border border-[#29313B] rounded-lg text-xs font-mono text-[#F87171] overflow-x-auto whitespace-pre-wrap">
              {this.state.error.message || String(this.state.error)}
            </pre>
          )}
          <div className="flex items-center gap-3 pt-2">
            <Button
              variant="primary"
              size="sm"
              icon={<RotateCcw className="w-3.5 h-3.5" />}
              onClick={this.handleReset}
            >
              Recover Module
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => window.location.reload()}
            >
              Reload Page
            </Button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
