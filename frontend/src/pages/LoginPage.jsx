import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'
import { toast } from 'react-toastify'
import { FiLock, FiMail, FiEye, FiEyeOff, FiShield, FiActivity } from 'react-icons/fi'

export default function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const { login } = useAuth()
  const navigate = useNavigate()

  const handleSubmit = async (e) => {
    e.preventDefault()
    setLoading(true)

    try {
      const result = await login(email, password)
      if (result.success) {
        toast.success('Login successful')
      } else {
        toast.error(result.message || 'Login failed')
      }
    } catch (error) {
      toast.error('An error occurred during login')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-dark-darker flex">
      {/* Background effects */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="login-grid-bg absolute inset-0 opacity-[0.03]" />
        <div className="absolute top-1/4 -left-32 w-96 h-96 bg-cyber-blue/10 rounded-full blur-[128px]" />
        <div className="absolute bottom-1/4 -right-32 w-96 h-96 bg-cyber-purple/10 rounded-full blur-[128px]" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-cyber-teal/5 rounded-full blur-[160px]" />
      </div>

      {/* Left branding panel - hidden on mobile */}
      <div className="hidden lg:flex lg:w-1/2 relative items-center justify-center p-12">
        <div className="relative z-10 max-w-md text-center">
          <div className="inline-flex items-center justify-center w-20 h-20 rounded-2xl bg-gradient-to-br from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/20 mb-8 login-float">
            <FiShield className="w-10 h-10 text-cyber-blue" />
          </div>
          <h1 className="text-4xl font-bold text-white mb-4 tracking-tight">
            UTDRS
          </h1>
          <p className="text-lg text-gray-400 mb-8 leading-relaxed">
            Unified Threat Detection & Response System
          </p>

          {/* Feature highlights */}
          <div className="space-y-4 text-left">
            {[
              { icon: FiActivity, text: 'Real-time threat monitoring' },
              { icon: FiShield, text: 'Advanced threat detection' },
              { icon: FiLock, text: 'Secure access controls' },
            ].map((feature, i) => (
              <div key={i} className="flex items-center gap-3 px-4 py-3 rounded-lg bg-white/[0.03] border border-white/[0.05]">
                <feature.icon className="w-5 h-5 text-cyber-teal flex-shrink-0" />
                <span className="text-sm text-gray-300">{feature.text}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Right form panel */}
      <div className="flex-1 flex items-center justify-center px-4 sm:px-6 lg:px-8 relative z-10">
        <div className="w-full max-w-md">
          {/* Mobile branding */}
          <div className="lg:hidden text-center mb-8">
            <div className="inline-flex items-center justify-center w-14 h-14 rounded-xl bg-gradient-to-br from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/20 mb-4">
              <FiShield className="w-7 h-7 text-cyber-blue" />
            </div>
            <h1 className="text-2xl font-bold text-white">UTDRS</h1>
            <p className="text-sm text-gray-400 mt-1">Unified Threat Detection & Response System</p>
          </div>

          {/* Login card */}
          <div className="login-card rounded-2xl p-8 sm:p-10">
            <div className="mb-8">
              <h2 className="text-2xl font-semibold text-white tracking-tight">
                Welcome back
              </h2>
              <p className="text-sm text-gray-400 mt-1">
                Sign in to access your dashboard
              </p>
            </div>

            <form className="space-y-5" onSubmit={handleSubmit}>
              {/* Email field */}
              <div>
                <label htmlFor="email" className="block text-sm font-medium text-gray-300 mb-1.5">
                  Email address
                </label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                    <FiMail className="h-[18px] w-[18px] text-gray-500 group-focus-within:text-cyber-blue transition-colors duration-200" />
                  </div>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="login-input block w-full pl-10 pr-4 py-2.5 text-sm text-white placeholder-gray-500 bg-dark-darker/60 border border-dark-light/60 rounded-lg focus:ring-2 focus:ring-cyber-blue/40 focus:border-cyber-blue/60 transition-all duration-200"
                    placeholder="you@example.com"
                  />
                </div>
              </div>

              {/* Password field */}
              <div>
                <label htmlFor="password" className="block text-sm font-medium text-gray-300 mb-1.5">
                  Password
                </label>
                <div className="relative group">
                  <div className="absolute inset-y-0 left-0 pl-3.5 flex items-center pointer-events-none">
                    <FiLock className="h-[18px] w-[18px] text-gray-500 group-focus-within:text-cyber-blue transition-colors duration-200" />
                  </div>
                  <input
                    id="password"
                    name="password"
                    type={showPassword ? 'text' : 'password'}
                    autoComplete="current-password"
                    required
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="login-input block w-full pl-10 pr-11 py-2.5 text-sm text-white placeholder-gray-500 bg-dark-darker/60 border border-dark-light/60 rounded-lg focus:ring-2 focus:ring-cyber-blue/40 focus:border-cyber-blue/60 transition-all duration-200"
                    placeholder="Enter your password"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-3.5 flex items-center text-gray-500 hover:text-gray-300 transition-colors duration-200"
                  >
                    {showPassword ? (
                      <FiEyeOff className="h-[18px] w-[18px]" />
                    ) : (
                      <FiEye className="h-[18px] w-[18px]" />
                    )}
                  </button>
                </div>
              </div>

              {/* Remember me & Forgot password */}
              <div className="flex items-center justify-between pt-0.5">
                <div className="flex items-center">
                  <input
                    id="remember-me"
                    name="remember-me"
                    type="checkbox"
                    className="h-4 w-4 rounded border-dark-light bg-dark-darker/60 text-cyber-blue focus:ring-cyber-blue/40 focus:ring-offset-0 transition-colors duration-200"
                  />
                  <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-400">
                    Remember me
                  </label>
                </div>
                <a href="#" className="text-sm text-cyber-blue hover:text-cyber-teal transition-colors duration-200">
                  Forgot password?
                </a>
              </div>

              {/* Submit button */}
              <div className="pt-2">
                <button
                  type="submit"
                  disabled={loading}
                  className="login-btn w-full flex items-center justify-center gap-2 py-2.5 px-4 text-sm font-medium text-white rounded-lg bg-gradient-to-r from-cyber-blue to-cyber-blue/80 hover:from-cyber-blue hover:to-cyber-teal focus:outline-none focus:ring-2 focus:ring-cyber-blue/40 focus:ring-offset-2 focus:ring-offset-dark-darker disabled:opacity-50 disabled:cursor-not-allowed transition-all duration-300"
                >
                  {loading ? (
                    <>
                      <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Signing in...
                    </>
                  ) : (
                    'Sign in'
                  )}
                </button>
              </div>
            </form>

            {/* Divider */}
            <div className="relative mt-8">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-dark-light/40"></div>
              </div>
              <div className="relative flex justify-center text-xs">
                <span className="px-3 bg-dark text-gray-500">
                  Need an account? Contact support
                </span>
              </div>
            </div>
          </div>

          {/* Footer */}
          <p className="mt-6 text-center text-xs text-gray-600">
            Protected by enterprise-grade encryption
          </p>
        </div>
      </div>
    </div>
  )
}
