<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Str;
use Symfony\Component\Yaml\Yaml;

class CourseController extends Controller
{
    public function index()
    {
        $modules = $this->getModules();
        return view('course.index', compact('modules'));
    }

    public function courseGuide()
    {
        $modules = $this->getModules();
        return view('course.guide', compact('modules'));
    }

    public function module($module)
    {
        $dir = resource_path('course-content/' . $module);
        $path = $dir . '/index.md';
        if (!File::exists($path)) {
            abort(404);
        }
        $content = File::get($path);
        $meta = [];
        if (preg_match('/^---\s*(.*?)\s*---\s*(.*)$/s', $content, $matches)) {
            $meta = Yaml::parse($matches[1]);
            $markdown = $matches[2];
        } else {
            $markdown = $content;
        }
        $title = $meta['title'] ?? $this->extractTitle($markdown);
        $labs = $meta['labs'] ?? [];
        $video = $meta['video'] ?? null;
        $diagram = $meta['diagram'] ?? null;
        $caseStudies = $meta['case_studies'] ?? [];
        $modules = $this->getModules();
        return view('course.module', compact('modules', 'module', 'title', 'markdown', 'labs', 'video', 'diagram', 'caseStudies'));
    }

    public function lab($lab)
    {
        $labPath = resource_path('course-content/labs/' . $lab . '.md');
        
        if (!File::exists($labPath)) {
            abort(404);
        }
        
        $content = File::get($labPath);
        $title = $this->extractTitle($content);
        $modules = $this->getModules();
        return view('course.lab', compact('modules', 'lab', 'title', 'content'));
    }

    public function resources()
    {
        $modules = $this->getModules();
        return view('course.resources', compact('modules'));
    }
    
    /**
     * Get a list of modules by scanning markdown directories.
     */
    private function getModules()
    {
        $modules = [];
        $dirs = File::directories(resource_path('course-content'));
        foreach ($dirs as $dir) {
            $slug = basename($dir);
            if (in_array($slug, ['labs', 'resources'])) {
                continue;
            }
            $path = $dir . '/index.md';
            if (!File::exists($path)) {
                continue;
            }
            $content = File::get($path);
            if (preg_match('/^---\s*(.*?)\s*---\s*(.*)$/s', $content, $matches)) {
                $meta = Yaml::parse($matches[1]);
                $title = $meta['title'] ?? $this->extractTitle($matches[2]);
            } else {
                $title = $this->extractTitle($content);
            }
            $modules[$slug] = $title;
        }
        return $modules;
    }

    private function extractTitle($content)
    {
        if (preg_match('/^#\s+(.+)$/m', $content, $matches)) {
            return $matches[1];
        }
        return 'Untitled';
    }
}
