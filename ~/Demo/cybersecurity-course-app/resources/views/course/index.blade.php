@extends('layouts.app')

@section('content')
<div class="bg-white rounded-lg shadow-lg p-8">
    <div class="prose prose-lg max-w-none">
        {!! $content !!}
    </div>
    
    <div class="mt-12 grid md:grid-cols-2 gap-6">
        <div class="bg-blue-50 rounded-lg p-6">
            <h3 class="text-lg font-bold text-blue-900 mb-3">🚀 Quick Start</h3>
            <p class="text-blue-700 mb-4">New to cybersecurity? Start with the fundamentals!</p>
            <a href="{{ route('course.module', '1-fundamentals') }}" class="inline-block bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700 transition">
                Start Module 1
            </a>
        </div>
        
        <div class="bg-green-50 rounded-lg p-6">
            <h3 class="text-lg font-bold text-green-900 mb-3">📖 Course Guide</h3>
            <p class="text-green-700 mb-4">Learn how to navigate this course effectively.</p>
            <a href="{{ route('course.guide') }}" class="inline-block bg-green-600 text-white px-4 py-2 rounded hover:bg-green-700 transition">
                View Course Guide
            </a>
        </div>
    </div>
</div>
@endsection 