import { useCallback, useEffect, useState } from 'react';
import { ApiEnvelope } from '../services/apiClient';

export function useApiQuery<T>(fetcher: () => Promise<ApiEnvelope<T>>) {
  const [data, setData] = useState<T | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [isDemoPreview, setIsDemoPreview] = useState<boolean>(true);

  const execute = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const response = await fetcher();
      setData(response.data);
      setIsDemoPreview(response.meta.is_demo_preview);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unexpected API error');
    } finally {
      setIsLoading(false);
    }
  }, [fetcher]);

  useEffect(() => {
    execute();
  }, [execute]);

  return { data, isLoading, error, isDemoPreview, refetch: execute };
}
