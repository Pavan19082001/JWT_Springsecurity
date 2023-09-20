package com.model;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

//@Component
public class Course {
	
	private int courseId;
	private String courseName;
	private List<Integer> starRating=new ArrayList<Integer>();
	int noOfUsersEnrolled;
	int duration;

	public int getCourseId() {	return courseId;
	}
	public void setCourseId(int courseId) {
		this.courseId = courseId;
	}
	public String getCourseName() {
		return courseName;
	}
	public void setCourseName(String courseName) {
		this.courseName = courseName;
	}
	
	public int getNoOfUsersEnrolled() {
		return noOfUsersEnrolled;
	}

	public void setNoOfUsersEnrolled(int noOfUsersEnrolled) {
		this.noOfUsersEnrolled = noOfUsersEnrolled;
	}
	public int getDuration() {
		return duration;
	}
	public void setDuration(int duration) {
		this.duration = duration;
	}
	public Course() {
		super();
	}
	public List<Integer> getStarRating() {
		return starRating;
	}
	public void setStarRating(List<Integer> starRating) {
		this.starRating = starRating;
	}
	public Course(int courseId, String courseName, List<Integer> starRating, int noOfUsersEnrolled, int duration) {
		super();
		this.courseId = courseId;
		this.courseName = courseName;
		this.starRating = starRating;
		this.noOfUsersEnrolled = noOfUsersEnrolled;
		this.duration = duration;
	}	

}
