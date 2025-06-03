@extends('layouts.app')

@section('content')
<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <div class="text-center mb-5">
                <h1 class="display-4 fw-bold">Cybersecurity Course</h1>
                <p class="lead text-muted">Learn the fundamentals of cybersecurity through hands-on labs and practical exercises</p>
            </div>

            <div class="row g-4">
                <div class="col-md-6">
                    <div class="card h-100 shadow-sm">
                        <div class="card-body">
                            <h5 class="card-title">📚 Course Guide</h5>
                            <p class="card-text">Get started with our comprehensive guide covering all course modules and learning objectives.</p>
                            <a href="{{ route('course.guide') }}" class="btn btn-primary">View Course Guide</a>
                        </div>
                    </div>
                </div>

                @foreach($modules as $slug => $title)
                <div class="col-md-6">
                    <div class="card h-100 shadow-sm">
                        <div class="card-body">
                            <h5 class="card-title">📖 {{ $title }}</h5>
                            <p class="card-text">Explore the content and hands-on labs for {{ $title }}.</p>
                            <a href="{{ route('course.module', $slug) }}" class="btn btn-outline-primary">Explore Module</a>
                        </div>
                    </div>
                </div>
                @endforeach
            </div>

            <div class="text-center mt-5">
                <a href="{{ route('course.resources') }}" class="btn btn-secondary">View Additional Resources</a>
            </div>
        </div>
    </div>
</div>
@endsection 