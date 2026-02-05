// Type declarations for framer-motion
// framer-motion ships with its own types, but bundler mode may not resolve them
declare module 'framer-motion' {
  import * as React from 'react';

  export interface MotionProps {
    initial?: object | string | boolean;
    animate?: object | string;
    exit?: object | string;
    transition?: object;
    variants?: object;
    whileHover?: object | string;
    whileTap?: object | string;
    whileFocus?: object | string;
    whileInView?: object | string;
    className?: string;
    style?: React.CSSProperties;
    children?: React.ReactNode;
    key?: React.Key;
    layout?: boolean | string;
    layoutId?: string;
    [key: string]: unknown;
  }

  type MotionComponent<T extends keyof JSX.IntrinsicElements> = React.ForwardRefExoticComponent<
    MotionProps & JSX.IntrinsicElements[T] & React.RefAttributes<Element>
  >;

  export const motion: {
    div: MotionComponent<'div'>;
    span: MotionComponent<'span'>;
    p: MotionComponent<'p'>;
    a: MotionComponent<'a'>;
    button: MotionComponent<'button'>;
    ul: MotionComponent<'ul'>;
    li: MotionComponent<'li'>;
    img: MotionComponent<'img'>;
    svg: MotionComponent<'svg'>;
    path: MotionComponent<'path'>;
    circle: MotionComponent<'circle'>;
    section: MotionComponent<'section'>;
    article: MotionComponent<'article'>;
    header: MotionComponent<'header'>;
    footer: MotionComponent<'footer'>;
    nav: MotionComponent<'nav'>;
    main: MotionComponent<'main'>;
    form: MotionComponent<'form'>;
    input: MotionComponent<'input'>;
    [key: string]: MotionComponent<keyof JSX.IntrinsicElements>;
  };

  export interface AnimatePresenceProps {
    children?: React.ReactNode;
    initial?: boolean;
    mode?: 'sync' | 'wait' | 'popLayout';
    onExitComplete?: () => void;
  }

  export const AnimatePresence: React.FC<AnimatePresenceProps>;

  export function useAnimation(): {
    start: (definition: object | string) => Promise<void>;
    stop: () => void;
    set: (definition: object) => void;
  };

  export function useMotionValue<T>(initial: T): {
    get: () => T;
    set: (value: T) => void;
    onChange: (callback: (value: T) => void) => () => void;
  };

  export function useTransform<T, U>(
    value: { get: () => T },
    transform: (value: T) => U
  ): { get: () => U };

  export function useSpring(
    value: { get: () => number },
    config?: object
  ): { get: () => number };

  export interface Variants {
    [key: string]: object;
  }
}
