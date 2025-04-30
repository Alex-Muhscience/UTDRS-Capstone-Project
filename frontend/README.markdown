# 🛡️ UTDRS Frontend - Unified Threat Detection and Response System

![UTDRS Logo](src\assets\image.jpg)

Welcome to the **Unified Threat Detection and Response System (UTDRS)** frontend, a modern, responsive, Multi-Page Application (MPA) built with **React**, **Tailwind CSS**, and **Vite**. Designed for small and medium enterprises (SMEs), UTDRS provides real-time cybersecurity monitoring, threat detection, and response management. This frontend integrates seamlessly with a Flask/FastAPI backend and MongoDB database, delivering a sleek, cybersecurity-inspired interface for **Admins** (system managers) and **Users** (SME cybersecurity personnel).

🌟 **Key Features**:

- 📊 Real-time dashboards with interactive threat and network traffic charts.
- 🖥️ Separate Admin Control Panel and User Portal for role-specific workflows.
- 🔒 Secure authentication with JWT and role-based access control (RBAC).
- 📡 WebSocket-powered live updates for alerts and device status.
- 📈 Three license tiers (Basic, Pro, Enterprise) with 30-day trials.
- 📱 Mobile-responsive, dark-themed UI with neon accents, inspired by Splunk and Darktrace.

---

## 📋 Table of Contents

- [🛡️ UTDRS Frontend - Unified Threat Detection and Response System](#️-utdrs-frontend---unified-threat-detection-and-response-system)
  - [📋 Table of Contents](#-table-of-contents)
  - [🌐 Project Overview](#-project-overview)
  - [🚀 Features](#-features)
    - [Admin Features](#admin-features)
    - [User Features](#user-features)
    - [Enhanced Features](#enhanced-features)
  - [🛠️ Tech Stack](#️-tech-stack)
  - [📁 Project Structure](#-project-structure)
  - [🔧 Prerequisites](#-prerequisites)
  - [🏗️ Setup Instructions](#️-setup-instructions)
  - [▶️ Running Locally](#️-running-locally)
  - [🏭 Building for Production](#-building-for-production)
  - [🐳 Deploying with Docker](#-deploying-with-docker)
  - [🌐 API Integration](#-api-integration)
  - [🔑 Environment Variables](#-environment-variables)
  - [🤝 Contributing](#-contributing)
  - [📜 License](#-license)
  - [📬 Contact](#-contact)

---

## 🌐 Project Overview

UTDRS is a comprehensive cybersecurity platform designed to protect SMEs from evolving threats. It integrates network security, endpoint protection, and application vulnerability management into a unified solution. The frontend is an MPA, with separate HTML pages for each major section (e.g., Dashboard, Device Management), powered by React for dynamic components. Deployed via Docker and Nginx, it ensures scalability and performance.

The system supports two user roles:

- **Admins**: Manage the platform, clients, licenses, and system configurations.
- **Users**: Monitor and secure their SME’s infrastructure, devices, and applications.

---

## 🚀 Features

### Admin Features

- **Dashboard** (`/admin/dashboard`): Real-time charts for user activity, threat distribution, and system health. Filter by time, client, or threat type.
- **User Management** (`/admin/users`): Create, edit, or suspend client accounts. Manage licenses (Basic, Pro, Enterprise) and track usage.
- **Analytics** (`/admin/analytics`): Aggregate threat data across clients, with exportable bar, pie, and line charts for business insights.
- **Reports** (`/admin/reports`): Generate and schedule client-specific or system-wide reports (weekly, monthly, yearly) in PDF/CSV.
- **Support Requests** (`/admin/support`): Manage client tickets with rich-text replies and automated assignment.
- **Settings** (`/admin/settings`): Configure system settings, security policies (e.g., MFA), and branding for white-labeling.

### User Features

- **Dashboard** (`/user/dashboard`): Visualize threat distributions, network traffic, and device status with real-time widgets and filters.
- **Account Profile** (`/user/profile`): View/edit company details, license status, and billing information.
- **Reports** (`/user/reports`): Generate detailed reports on threats, vulnerabilities, and devices (hourly, daily, weekly, monthly, yearly).
- **Device Management** (`/user/devices`): Monitor devices (IP, MAC, OS, status), scan for threats, configure policies, or isolate devices.
- **Vulnerabilities** (`/user/vulnerabilities`): List and prioritize application/device vulnerabilities with CVE details and remediation actions.
- **Threats and Attacks** (`/user/threats`): View incidents with MITRE ATT&CK mappings, escalate to Admins, or trigger playbooks.
- **Settings** (`/user/settings`): Customize notifications, device policies, and UI preferences (theme, language).

### Enhanced Features

- 🌍 **Threat Intelligence Feed**: Contextualize attacks with global threat indicators.
- 🎮 **Gamification**: Reward Users with badges for timely threat mitigation.
- 🤖 **AI-Driven Insights**: Predict potential threats using machine learning.
- 📂 **Audit Logs**: Track all actions for accountability.
- 📱 **Mobile Optimization**: Responsive design for tablets and smartphones.
- 🧙 **Onboarding Wizard**: Interactive setup for new Users.

---

## 🛠️ Tech Stack

| **Category**         | **Technology**                     |
|-----------------------|------------------------------------|
| **Framework**         | React (v18) with Vite             |
| **Styling**           | Tailwind CSS                      |
| **State Management**  | React Context, Redux Toolkit      |
| **Charts**            | Recharts                          |
| **Real-Time**         | Socket.IO (WebSockets)            |
| **API Client**        | Axios                             |
| **Build Tool**        | Vite                              |
| **Deployment**        | Docker, Nginx                     |
| **Backend**           | Flask/FastAPI (assumed)           |
| **Database**          | MongoDB                           |
| **Security**          | JWT, HTTPS, CSRF Protection       |

---

## 📁 Project Structure

```
utdrs-frontend/
├── Dockerfile                # Docker configuration for building and deploying
├── nginx.conf                # Nginx configuration for MPA routing
├── package.json              # Node.js dependencies and scripts
├── vite.config.js            # Vite configuration
├── tailwind.config.js        # Tailwind CSS configuration
├── public/                   # Static assets and HTML pages
│   ├── favicon.ico
│   ├── logo.png
│   ├── admin/                # Admin HTML pages
│   │   ├── dashboard.html
│   │   ├── users.html
│   │   ├── analytics.html
│   │   ├── reports.html
│   │   ├── support.html
│   │   ├── settings.html
│   ├── user/                 # User HTML pages
│   │   ├── dashboard.html
│   │   ├── profile.html
│   │   ├── reports.html
│   │   ├── devices.html
│   │   ├── vulnerabilities.html
│   │   ├── threats.html
│   │   ├── settings.html
│   ├── login.html
│   ├── 404.html
│   ├── 403.html
├── src/                      # Source code
│   ├── assets/               # Fonts and icons
│   ├── components/           # Reusable React components
│   │   ├── shared/           # Shared components (Navbar, Sidebar, etc.)
│   │   ├── admin/            # Admin-specific components
│   │   ├── user/             # User-specific components
│   │   ├── auth/             # Authentication components
│   ├── api/                  # API clients (Axios, WebSocket)
│   ├── context/              # React Context for state
│   ├── pages/                # Page-specific React entry points
│   │   ├── admin/
│   │   ├── user/
│   │   ├── LoginPage.jsx
│   │   ├── NotFoundPage.jsx
│   ├── styles/               # CSS files
│   ├── main.jsx              # Main React entry point
│   ├── index.css             # Global styles
├── README.md                 # This file
```

---

## 🔧 Prerequisites

Before setting up the project, ensure you have:

- **Node.js** (v18 or higher): [Download](https://nodejs.org/)
- **Docker**: [Download](https://www.docker.com/)
- **Git**: [Download](https://git-scm.com/)
- **Backend**: A running Flask/FastAPI backend with MongoDB, exposing `/api` and `/ws` endpoints.
- **Text Editor**: VS Code recommended for development.

---

## 🏗️ Setup Instructions

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/your-org/utdrs-frontend.git
   cd utdrs-frontend
   ```

2. **Install Dependencies**:

   ```bash
   npm install
   ```

3. **Configure Environment Variables**:
   Create a `.env` file in the root directory:

   ```env
   VITE_API_URL=http://backend:8000
   VITE_WS_URL=ws://backend:8000/ws
   ```

   Adjust URLs to match your backend setup.

---

## ▶️ Running Locally

1. **Start the Development Server**

   ```bash
   npm run dev
   ```

   Open `http://localhost:5173/login` in your browser.

2. **Access Pages**:
   - Admin: `http://localhost:5173/admin/dashboard`
   - User: `http://localhost:5173/user/dashboard`
   - Login: `http://localhost:5173/login`

3. **Hot Reloading**:
   Vite enables live reloading for faster development.

---

## 🏭 Building for Production

1. **Build the Project**

   ```bash
   npm run build
   ```

   Outputs optimized assets to the `dist/` directory.

2. **Preview the Build**:

   ```bash
   npm run preview
   ```

   Serves the production build locally.

---

## 🐳 Deploying with Docker

1. **Build the Docker Image**:

   ```bash
   docker build -t utdrs-frontend .
   ```

2. **Run the Container**:

   ```bash
   docker run -p 80:80 --env-file .env utdrs-frontend
   ```

   Access the app at `http://localhost`.

3. **Docker Compose (Optional)**:

   If using with a backend, create a `docker-compose.yml`:

   ```yaml
   version: '3.8'
   services:
     frontend:
       image: utdrs-frontend
       ports:
         - "80:80"
       env_file:
         - .env
       depends_on:
         - backend
     backend:
       image: utdrs-backend # Replace with your backend image
       ports:
         - "8000:8000"
   ```

4. **Nginx Routing**:
   The `nginx.conf` routes each page (e.g., `/admin/dashboard`) to its HTML file and proxies `/api` and `/ws` to the backend.

---

## 🌐 API Integration

The frontend connects to the Flask/FastAPI backend via:

- **REST Endpoints**:
  - Auth: `POST /api/login`, `POST /api/refresh`, `POST /api/logout`
  - Admin: `/api/admin/users`, `/api/admin/licenses`, `/api/admin/analytics`, etc.
  - User: `/api/user/profile`, `/api/user/dashboard`, `/api/user/devices`, etc.
- **WebSocket**: `/ws/alerts` for real-time updates.
- **Payloads**: JSON with MongoDB `_id` fields.

Ensure the backend is running and accessible at the URLs specified in `.env`.

---

## 🔑 Environment Variables

| **Variable**       | **Description**                          | **Default**                  |
|--------------------|------------------------------------------|------------------------------|
| `VITE_API_URL`     | Backend API URL                          | `http://backend:8000`        |
| `VITE_WS_URL`      | WebSocket URL for real-time updates      | `ws://backend:8000/ws`       |

Update `.env` to match your backend configuration.

---

## 🤝 Contributing

We welcome contributions! Follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/your-feature`.
3. Commit changes: `git commit -m "Add your feature"`.
4. Push to the branch: `git push origin feature/your-feature`.
5. Open a Pull Request.

Please adhere to our [Code of Conduct](CODE_OF_CONDUCT.md) and use meaningful commit messages.

---

## 📜 License

This project is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.

---

## 📬 Contact

For questions or support, reach out to:

- **Email**: info.ak.computerscience@gmail.com
- **GitHub Issues**: [Create an Issue](https://github.com/Alex-Muhscience/utdrs-frontend/issues)
- **Documentation**: [UTDRS Docs](https://docs.utdrs.com)

🔒 Stay secure with UTDRS!