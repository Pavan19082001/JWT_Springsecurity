package com.service;

import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

import com.model.Course;

@Service
public class CourseService {

	private static List<Course> courseList=new ArrayList<Course>();

	public CourseService() {
		List<Integer> starRating=new ArrayList<Integer>();
		starRating.add(4);starRating.add(1);starRating.add(5);
		List<Integer> starRating1=new ArrayList<Integer>();
		starRating1.add(3);starRating1.add(2);starRating1.add(4);
		List<Integer> starRating2=new ArrayList<Integer>();
		starRating2.add(1);starRating2.add(5);starRating2.add(3);
		courseList.add(new Course(101,"Spring Core",starRating,200,180));
		courseList.add(new Course(102,"Java",starRating1,800,120));
		courseList.add(new Course(103,"Java",starRating1,200,120));
		courseList.add(new Course(104,"Oracle",starRating2,20,60));
		courseList.add(new Course(105,"Oracle",starRating2,900,60));
		courseList.add(new Course(106,"Spring Core",starRating,100,180));
	}
	
	
	public static List<Course> getCourseList() {
		return courseList;
	}


	public static void setCourseList(List<Course> courseList) {
		CourseService.courseList = courseList;
	}


	public Course addCourse(Course ass) {
		courseList.add(ass);
		return ass;
	}
	public Course updateCourseDuration(int courseId, int duration) {
		for(Course cu:courseList) {
			if(cu.getCourseId()==courseId)
			{
				cu.setDuration(duration);
				return cu;
			}
		}
		return null;
	}
	
	public List<Course> viewAllCourse()
	{
		return courseList;
	}
	
	public Course provideStarRating(int courseId, int starRating){
		for(Course ass:courseList) {
			if(ass.getCourseId()==courseId)
			{
				ass.getStarRating().add(starRating);
				return ass;
			}
		}
		return null;
	}

}
