import { afterEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
class TestEventSource { addEventListener() {} close() {} }
class TestResizeObserver { observe() {} unobserve() {} disconnect() {} }
vi.stubGlobal('EventSource', TestEventSource);
vi.stubGlobal('ResizeObserver', TestResizeObserver);
afterEach(() => cleanup());
