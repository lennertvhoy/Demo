<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ $title ?? 'Cybersecurity Course' }}</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css">
    <style>
        .prose pre {
            background-color: #2d2d2d;
            color: #f8f8f2;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
        }
        .prose code {
            background-color: #f3f4f6;
            padding: 0.125rem 0.25rem;
            border-radius: 0.25rem;
            font-size: 0.875rem;
        }
        .prose pre code {
            background-color: transparent;
            padding: 0;
        }
        .prose table {
            width: 100%;
            border-collapse: collapse;
        }
        .prose table th,
        .prose table td {
            border: 1px solid #e5e7eb;
            padding: 0.5rem;
        }
        .prose table th {
            background-color: #f9fafb;
            font-weight: 600;
        }
    </style>
</head>
<body class="bg-gray-50 min-h-screen">
    <!-- Navigation -->
    <nav class="bg-gray-900 text-white sticky top-0 z-50 shadow-lg">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div class="flex items-center justify-between h-16">
                <div class="flex items-center">
                    <a href="{{ route('course.index') }}" class="flex items-center">
                        <span class="text-xl font-bold">🔐 CyberSec Course</span>
                    </a>
                    <div class="hidden md:block ml-10">
                        <div class="flex items-baseline space-x-4">
                            <a href="{{ route('course.guide') }}" class="hover:bg-gray-700 px-3 py-2 rounded-md text-sm font-medium">Course Guide</a>
                            <div class="relative group">
                                <button class="hover:bg-gray-700 px-3 py-2 rounded-md text-sm font-medium">Modules ▼</button>
                                <div class="absolute left-0 mt-2 w-64 rounded-md shadow-lg bg-white ring-1 ring-black ring-opacity-5 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200">
                                    <div class="py-1">
                                        <a href="{{ route('course.module', '1-fundamentals') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Module 1: Fundamentals</a>
                                        <a href="{{ route('course.module', '2-network-security') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Module 2: Network Security</a>
                                        <a href="{{ route('course.module', '3-web-security') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Module 3: Web Security</a>
                                        <a href="{{ route('course.module', '4-cryptography') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Module 4: Cryptography</a>
                                        <a href="{{ route('course.module', '5-ethical-hacking') }}" class="block px-4 py-2 text-sm text-gray-700 hover:bg-gray-100">Module 5: Ethical Hacking</a>
                                    </div>
                                </div>
                            </div>
                            <a href="{{ route('course.lab', 'lab-1-network-recon') }}" class="hover:bg-gray-700 px-3 py-2 rounded-md text-sm font-medium">Labs</a>
                            <a href="{{ route('course.resources') }}" class="hover:bg-gray-700 px-3 py-2 rounded-md text-sm font-medium">Resources</a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        @yield('content')
    </main>

    <!-- Footer -->
    <footer class="bg-gray-800 text-white mt-12">
        <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div class="text-center">
                <p class="text-sm">© 2024 Cybersecurity Fundamentals Course</p>
                <p class="text-xs mt-2 text-gray-400">Remember: With great power comes great responsibility. Use your skills ethically and legally!</p>
            </div>
        </div>
    </footer>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-bash.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-python.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-php.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-sql.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
</body>
</html> 