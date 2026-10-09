'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';

export default function OracleRedirect() {
  const router = useRouter();
  useEffect(() => {
    router.replace('/prowl?view=oracle');
  }, [router]);
  return null;
}
