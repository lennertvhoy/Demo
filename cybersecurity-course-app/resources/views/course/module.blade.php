@extends('layouts.app')

@section('content')
<div class="container py-5">
    <div class="row">
        <div class="col-lg-8 mx-auto">
            <nav aria-label="breadcrumb">
                <ol class="breadcrumb">
                    <li class="breadcrumb-item"><a href="{{ route('course.index') }}">Home</a></li>
                    <li class="breadcrumb-item"><a href="{{ route('course.guide') }}">Course Guide</a></li>
                    <li class="breadcrumb-item active">{{ $title }}</li>
                </ol>
            </nav>

            <h1 class="display-4 mb-4">{{ $title }}</h1>

            @if($video)
            <div class="ratio ratio-16x9 mb-4">
                <iframe src="{{ $video }}" allowfullscreen></iframe>
            </div>
            @endif

            {!! \Illuminate\Support\Str::markdown($markdown) !!}

            @if(!empty($labs))
            <h2 class="h3 mt-5">Hands-on Labs</h2>
            <div class="row g-3 mb-5">
                @foreach($labs as $labSlug)
                <div class="col-md-6">
                    <div class="card h-100">
                        <div class="card-body">
                            <h5 class="card-title">🧪 {{ Str::headline(str_replace('-', ' ', $labSlug)) }}</h5>
                            <a href="{{ route('course.lab', $labSlug) }}" class="btn btn-primary btn-sm">Start Lab</a>
                        </div>
                    </div>
                </div>
                @endforeach
            </div>
            @endif

            @if(!empty($caseStudies))
            <h2 class="h3 mt-5">Case Studies</h2>
            <ul class="list-group mb-5">
                @foreach($caseStudies as $case)
                <li class="list-group-item">
                    <h5>{{ $case['title'] }}</h5>
                    <p class="mb-1 text-muted">{{ $case['description'] }}</p>
                    <a href="{{ $case['url'] }}" class="btn btn-sm btn-outline-primary">Read Case Study</a>
                </li>
                @endforeach
            </ul>
            @endif
            <div class="mt-5">
                <a href="{{ url()->previous() }}" class="btn btn-secondary">← Back</a>
            </div>
        </div>
    </div>
</div>
@endsection 