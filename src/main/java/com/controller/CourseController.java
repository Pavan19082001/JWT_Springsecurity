package com.controller;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.model.Course;
import com.service.CourseService;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/courseapp")
public class CourseController {

	@Autowired
	private CourseService service;

	@PreAuthorize("hasRole('ADMIN')")
	@PutMapping("/update/{courseId}/{duration}")
	public Course updateCourseDuration(@PathVariable int courseId, @PathVariable int duration) {
		return service.updateCourseDuration(courseId, duration);
	}

	@PreAuthorize("hasAnyRole('USER', 'ADMIN')")
	@GetMapping("/viewAllCourse")
	public List<Course> viewAllCourse() {
		return service.viewAllCourse();
	}

	@PreAuthorize("hasRole('USER')")
	@PutMapping("/starrating/{courseId}/{starRating}")
	public <List> Course provideStarRating(@PathVariable int courseId, @PathVariable int starRating) {
		return service.provideStarRating(courseId, starRating);
	}

}
