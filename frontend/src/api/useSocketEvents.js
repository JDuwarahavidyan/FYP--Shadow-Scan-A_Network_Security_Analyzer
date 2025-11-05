import { useEffect } from 'react';

export const useSocketEvents = (callback) => {
  useEffect(() => {
    const interval = setInterval(() => {
      // Future WebSocket integration here
      if (callback) callback();
    }, 1000);
    return () => clearInterval(interval);
  }, [callback]);
};
