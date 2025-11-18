import React from "react";
import { spacing } from "@/tokens/design-tokens";

interface CardProps extends React.HTMLAttributes<HTMLDivElement> {
  padding?: "sm" | "md" | "lg" | "xl";
  shadow?: "sm" | "md" | "lg" | "xl" | "none";
  hoverEffect?: boolean;
  children: React.ReactNode;
}

const Card = React.forwardRef<HTMLDivElement, CardProps>(
  (
    {
      padding = "lg",
      shadow = "md",
      hoverEffect = false,
      children,
      className = "",
      ...props
    },
    ref
  ) => {
    const paddingStyles = {
      sm: `p-${spacing.sm}`,
      md: `p-${spacing.md}`,
      lg: `p-${spacing.lg}`,
      xl: `p-${spacing.xl}`,
    };

    const shadowStyles = {
      none: "shadow-none",
      sm: "shadow-sm",
      md: "shadow-md",
      lg: "shadow-lg",
      xl: "shadow-xl",
    };

    return (
      <div
        ref={ref}
        className={`
          bg-white
          rounded-xl
          ${paddingStyles[padding]}
          ${shadowStyles[shadow]}
          ${
            hoverEffect
              ? "transition-all duration-200 hover:shadow-lg cursor-pointer"
              : ""
          }
          ${className}
        `}
        {...props}
      >
        {children}
      </div>
    );
  }
);

Card.displayName = "Card";

export default Card;
