import React, { useState, useEffect } from "react";
import Button from "@/components/Button";
import Card from "@/components/Card";
import Input from "@/components/Input";

interface ResetPasswordProps {
  token?: string;
  onBack?: () => void;
  onResetSuccess?: () => void;
}

const ResetPassword: React.FC<ResetPasswordProps> = ({
  token,
  onBack,
  onResetSuccess,
}) => {
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [validatingToken, setValidatingToken] = useState(true);
  const [tokenValid, setTokenValid] = useState(false);
  const [success, setSuccess] = useState(false);
  const [passwordStrength, setPasswordStrength] = useState<
    "weak" | "fair" | "good" | "strong"
  >("weak");

  // Get token from URL query params if not provided
  const urlToken =
    token || new URLSearchParams(window.location.search).get("token");

  // Validate token on mount
  useEffect(() => {
    if (!urlToken) {
      setError("Invalid or missing reset token");
      setValidatingToken(false);
      return;
    }

    const validateToken = async () => {
      try {
        const response = await fetch(
          `${import.meta.env.VITE_API_URL}/auth/validate-token`,
          {
            method: "GET",
            headers: {
              "Content-Type": "application/json",
            },
            body: JSON.stringify({ token: urlToken }),
          }
        );

        if (!response.ok) {
          setError(
            "Password reset link has expired. Please request a new one."
          );
          setTokenValid(false);
        } else {
          setTokenValid(true);
        }
      } catch (err) {
        setError("Unable to validate reset link. Please try again.");
      } finally {
        setValidatingToken(false);
      }
    };

    validateToken();
  }, [urlToken]);

  // Calculate password strength
  useEffect(() => {
    const strength = calculatePasswordStrength(password);
    setPasswordStrength(strength);
  }, [password]);

  const calculatePasswordStrength = (
    pwd: string
  ): "weak" | "fair" | "good" | "strong" => {
    let strength = 0;

    if (pwd.length >= 8) strength++;
    if (pwd.length >= 12) strength++;
    if (/[a-z]/.test(pwd) && /[A-Z]/.test(pwd)) strength++;
    if (/[0-9]/.test(pwd)) strength++;
    if (/[!@#$%^&*]/.test(pwd)) strength++;

    if (strength <= 1) return "weak";
    if (strength === 2) return "fair";
    if (strength === 3) return "good";
    return "strong";
  };

  const getPasswordStrengthColor = () => {
    const colors = {
      weak: "bg-red-500",
      fair: "bg-amber-500",
      good: "bg-blue-500",
      strong: "bg-green-500",
    };
    return colors[passwordStrength];
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    // Validate passwords match
    if (password !== confirmPassword) {
      setError("Passwords do not match");
      return;
    }

    // Validate password strength
    if (passwordStrength === "weak") {
      setError(
        "Password is too weak. Please use at least 8 characters with mixed case."
      );
      return;
    }

    setLoading(true);

    try {
      const response = await fetch(
        `${import.meta.env.VITE_API_URL}/auth/reset-password`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            token: urlToken,
            password,
            password_confirm: confirmPassword,
          }),
        }
      );

      const data = await response.json();

      if (!response.ok) {
        setError(data.detail || "Failed to reset password");
        return;
      }

      setSuccess(true);
      onResetSuccess?.();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "An error occurred. Please try again."
      );
    } finally {
      setLoading(false);
    }
  };

  if (validatingToken) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-50">
        <Card padding="lg" shadow="lg" className="w-full max-w-md text-center">
          <svg
            className="animate-spin h-8 w-8 text-blue-600 mx-auto mb-4"
            fill="none"
            viewBox="0 0 24 24"
          >
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
            />
          </svg>
          <p className="text-gray-600">Validating reset link...</p>
        </Card>
      </div>
    );
  }

  if (!tokenValid) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-50 px-4">
        <Card padding="lg" shadow="lg" className="w-full max-w-md">
          <div className="text-center">
            <div className="w-16 h-16 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                className="w-8 h-8 text-red-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 8v4m0 4v.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
                />
              </svg>
            </div>

            <h1 className="text-2xl font-semibold text-gray-900 mb-2">
              Link Expired
            </h1>
            <p className="text-gray-600 mb-6">{error}</p>

            <Button variant="primary" fullWidth onClick={onBack}>
              Back to Login
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  if (success) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-50 px-4">
        <Card padding="lg" shadow="lg" className="w-full max-w-md">
          <div className="text-center">
            <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
              <svg
                className="w-8 h-8 text-green-600"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>

            <h1 className="text-2xl font-semibold text-gray-900 mb-2">
              Password Reset Successful
            </h1>

            <p className="text-gray-600 mb-6">
              Your password has been reset. You can now log in with your new
              password.
            </p>

            <Button variant="primary" fullWidth onClick={onBack}>
              Go to Login
            </Button>
          </div>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-50 px-4">
      <Card padding="lg" shadow="lg" className="w-full max-w-md">
        <div className="text-center mb-8">
          <div className="text-4xl font-bold text-blue-600 mb-2">🔒</div>
          <h1 className="text-2xl font-semibold text-gray-900">
            Reset Password
          </h1>
          <p className="text-gray-600 text-sm mt-2">
            Enter a new password for your account.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          {error && (
            <div className="p-4 bg-red-50 border border-red-200 rounded-lg text-sm text-red-700">
              {error}
            </div>
          )}

          <div>
            <Input
              label="New Password"
              type="password"
              placeholder="Enter new password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              disabled={loading}
              icon={
                <svg
                  className="w-5 h-5 text-gray-400"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                  />
                </svg>
              }
            />

            {/* Password Strength Indicator */}
            {password && (
              <div className="mt-2">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-gray-600">
                    Strength:
                  </span>
                  <span className="text-xs font-semibold text-gray-700">
                    {passwordStrength.charAt(0).toUpperCase() +
                      passwordStrength.slice(1)}
                  </span>
                </div>
                <div className="h-1.5 bg-gray-200 rounded-full overflow-hidden">
                  <div
                    className={`h-full ${getPasswordStrengthColor()} transition-all`}
                    style={{
                      width: {
                        weak: "25%",
                        fair: "50%",
                        good: "75%",
                        strong: "100%",
                      }[passwordStrength],
                    }}
                  />
                </div>
              </div>
            )}

            <p className="mt-2 text-xs text-gray-500">
              At least 8 characters with uppercase, lowercase, number and
              special character
            </p>
          </div>

          <Input
            label="Confirm Password"
            type="password"
            placeholder="Confirm new password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            required
            disabled={loading}
            error={
              confirmPassword && password !== confirmPassword
                ? "Passwords do not match"
                : undefined
            }
            icon={
              <svg
                className="w-5 h-5 text-gray-400"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth={2}
                  d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
                />
              </svg>
            }
          />

          <Button
            type="submit"
            variant="primary"
            fullWidth
            loading={loading}
            disabled={
              !password ||
              !confirmPassword ||
              password !== confirmPassword ||
              loading
            }
          >
            Reset Password
          </Button>
        </form>

        <div className="mt-6 pt-6 border-t border-gray-200 text-center">
          <button
            onClick={onBack}
            className="text-sm text-blue-600 hover:text-blue-700 font-medium"
          >
            Back to Login
          </button>
        </div>
      </Card>
    </div>
  );
};

export default ResetPassword;
