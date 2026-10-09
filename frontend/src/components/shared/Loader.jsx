export default function Loader({ size = 'md', color = 'primary' }) {
    const sizeClasses = {
      sm: 'h-4 w-4',
      md: 'h-8 w-8',
      lg: 'h-12 w-12',
      xl: 'h-16 w-16'
    }
    
    const colorClasses = {
      primary: 'border-cyber-blue',
      secondary: 'border-cyber-teal',
      danger: 'border-danger',
      warning: 'border-warning',
      success: 'border-success'
    }
    
    return (
      <div className="flex items-center justify-center">
        <div className={`animate-spin rounded-full border-2 border-solid ${colorClasses[color]} ${sizeClasses[size]} border-t-transparent`}></div>
      </div>
    )
  }