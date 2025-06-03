@extends('layouts.app')

@section('content')
<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <h1 class="display-4 mb-4">Course Guide</h1>
            
            <div class="card mb-4">
                <div class="card-body">
                    <h2 class="h4 mb-3">Course Overview</h2>
                    <p>This comprehensive cybersecurity course is designed to take you from beginner to intermediate level in cybersecurity. Through hands-on labs, practical exercises, and real-world scenarios, you'll gain the skills needed to understand and implement cybersecurity best practices.</p>
                    
                    <h3 class="h5 mt-4">Learning Objectives</h3>
                    <ul>
                        <li>Understand fundamental cybersecurity concepts and terminology</li>
                        <li>Identify and mitigate common security vulnerabilities</li>
                        <li>Implement secure coding practices</li>
                        <li>Configure and manage network security</li>
                        <li>Apply cryptographic techniques for data protection</li>
                        <li>Conduct ethical hacking and penetration testing</li>
                    </ul>
                </div>
            </div>

            <h2 class="h3 mb-4">Course Modules</h2>

            <div class="accordion" id="modulesAccordion">
                @foreach($modules as $slug => $title)
                <div class="accordion-item">
                    <h2 class="accordion-header">
                        <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#{{ $slug }}">
                            {{ $title }}
                        </button>
                    </h2>
                    <div id="{{ $slug }}" class="accordion-collapse collapse" data-bs-parent="#modulesAccordion">
                        <div class="accordion-body">
                            <p>Explore the contents of {{ $title }}.</p>
                            <a href="{{ route('course.module', $slug) }}" class="btn btn-sm btn-primary">Start Module</a>
                        </div>
                    </div>
                </div>
                @endforeach
            </div>

            <div class="mt-5 text-center">
                <a href="{{ route('course.index') }}" class="btn btn-secondary">Back to Home</a>
            </div>
        </div>
    </div>
</div>
@endsection 