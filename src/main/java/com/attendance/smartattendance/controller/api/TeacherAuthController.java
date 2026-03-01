package com.attendance.smartattendance.controller.api;

import com.attendance.smartattendance.dto.*;
import com.attendance.smartattendance.entity.Student;
import com.attendance.smartattendance.entity.Teacher;
import com.attendance.smartattendance.repository.AttendanceRepository;
import com.attendance.smartattendance.repository.StudentRepository;
import com.attendance.smartattendance.repository.TeacherRepository;
import com.attendance.smartattendance.service.AttendanceService;
import com.attendance.smartattendance.service.EmailService;
import com.attendance.smartattendance.service.OtpService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/teacher")
public class TeacherAuthController {

    @Autowired private TeacherRepository teacherRepository;
    @Autowired private StudentRepository studentRepository;
    @Autowired private AttendanceRepository attendanceRepository;
    @Autowired private AttendanceService attendanceService;
    @Autowired private EmailService emailService;
    @Autowired private OtpService otpService;
    @Autowired private BCryptPasswordEncoder passwordEncoder;

    //  LOGIN
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody TeacherLoginRequest request,HttpSession session) {

    Teacher teacher = teacherRepository.findByTeacherId(request.getTeacherId())
            .orElseThrow(() -> new RuntimeException("Teacher not found"));

    if (!passwordEncoder.matches(request.getPassword(), teacher.getPassword())) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid password");
    }

    if (!teacher.isVerified()) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN)
           .body("Account not verified. Please verify your email.");
    }
    session.setAttribute("teacherId", teacher.getTeacherId());

    return ResponseEntity.ok("Login successful");
}


    //  REGISTER (now sends verification link)
    @PostMapping("/register")
    public ResponseEntity<String> register(@RequestBody Teacher teacher, HttpServletRequest request) {

        // 1. Email check (Unga DB-la already andha email irundha row-a delete pannidunga)
        if (teacherRepository.existsByEmail(teacher.getEmail())) {
            return ResponseEntity.badRequest().body("Email already in use");
        }

        // 2. Initial Setup
        teacher.setPassword(passwordEncoder.encode(teacher.getPassword()));
        teacher.setClassroomCode(UUID.randomUUID().toString().substring(0, 6));
        teacher.setVerificationToken(UUID.randomUUID().toString());
        teacher.setVerified(false);

        teacherRepository.save(teacher);

        // 3. Dynamic Link (Railway URL-a auto-va edukkum)
        String baseUrl = request.getRequestURL().toString().replace(request.getRequestURI(), "");
        String verifyLink = baseUrl + "/api/teacher/verify?token=" + teacher.getVerificationToken();

        // 4. Send Email
        try {
            emailService.sendMail(
                    teacher.getEmail(),
                    "Verify your account",
                    "Hi " + teacher.getName() + ",\n\nClick to verify: " + verifyLink
            );
            return ResponseEntity.ok("Teacher registered. Check your email!");
        } catch (Exception e) {

            return ResponseEntity.status(500).body("Mail Error: " + e.getMessage());
        }
    }

    // verification endpoint for registration
    @GetMapping("/verify")
    public String verifyRegistration(@RequestParam String token) {
        Teacher teacher = teacherRepository.findByVerificationToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));

        teacher.setVerified(true);
        teacher.setVerificationToken(null);
        teacherRepository.save(teacher);

        return "<h2>Account Verified Successfully ✅</h2>"
         + "<a href='/teacher/login'>Go to Login</a>";
    }

    //  FORGOT PASSWORD
    @PostMapping("/forgot-password")
    public String forgotPassword(@RequestBody ForgotPasswordRequest request) {

        Teacher teacher = teacherRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email"));

        String otp = String.valueOf((int) (Math.random() * 900000) + 100000);

        teacher.setResetOtp(otp);
        teacher.setOtpExpiry(LocalDateTime.now().plusMinutes(2));
        teacherRepository.save(teacher);

        emailService.sendMail(
                teacher.getEmail(),
                "Password Reset OTP",
                "Your OTP is: " + otp + " (Valid for 2 minutes)"
        );

        System.out.println("Your OTP: "+otp);

        return "OTP SENT";
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestBody VerifyOtpRequest request) {

        Teacher teacher = teacherRepository.findByEmail(request.getEmail())
                .orElseThrow(() ->
                        new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email"));

        if (!request.getOtp().equals(teacher.getResetOtp())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid OTP");
        }

        if (teacher.getOtpExpiry().isBefore(LocalDateTime.now())) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "OTP expired");
        }

        teacher.setResetOtp(null);
        teacherRepository.save(teacher);
        return "OTP VERIFIED";
    }

    @PostMapping("/reset-password")
    public String resetPassword(@RequestBody ResetPasswordRequest request) {

        Teacher teacher = teacherRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Email not found"));

        teacher.setPassword(passwordEncoder.encode(request.getNewPassword()));
        teacher.setResetOtp(null);
        teacher.setOtpExpiry(null);
        teacherRepository.save(teacher);

        return "PASSWORD UPDATED";
    }

    //  STUDENT MANAGEMENT

    // existing teacher-specific path stays
    @PostMapping("/add-student")
    public ResponseEntity<?> addStudent(
            @RequestBody Student student,HttpSession session) {
        
        String teacherID = (String) session.getAttribute("teacherId");

        Teacher teacher = teacherRepository.findByTeacherId(teacherID)
                .orElseThrow(() -> new RuntimeException("Teacher not found"));

        student.setClassroomCode(teacher.getClassroomCode());
        student.setPresentToday(null);
        studentRepository.save(student);

        return ResponseEntity.ok("Student added successfully");
    }

    // ✅ Edit / Update Student (Teacher only)
    @PutMapping("/edit-student/{id}")
    public ResponseEntity<?> editStudent(
            @PathVariable Long id,
            @RequestBody Student updatedStudent) {

        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Student not found"));

        student.setName(updatedStudent.getName());
        student.setEmail(updatedStudent.getEmail());

        studentRepository.save(student);

        return ResponseEntity.ok("Student updated successfully");
    }

    @PutMapping("/update-student-attendance/{studentId}")
    public ResponseEntity<?> updateStudentAttendance(
            @PathVariable Long studentId,
            @RequestBody Map<String, String> body,
            HttpSession session
    ) {
        String attendanceValue = body.get("attendance");
        String teacherId = (String) session.getAttribute("teacherId");
        
        if (teacherId == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Teacher not authenticated");
        }

        // Verify student exists
        studentRepository.findById(studentId)
                .orElseThrow(() -> new RuntimeException("Student not found"));

        // Check if 5 minutes have passed since OTP was sent
        if (!attendanceService.canManuallyUpdateAttendance(studentId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Manual attendance update is only allowed 5 minutes after OTP is sent");
        }

        attendanceService.updateAttendance(studentId, attendanceValue);

        return ResponseEntity.ok("Attendance updated successfully");
    }

    @GetMapping("/all-students")
    public List<StudentDashboardDTO> getAllStudents(HttpSession session) {

        String teacherId = (String) session.getAttribute("teacherId");

        Teacher teacher = teacherRepository.findByTeacherId(teacherId)
                .orElseThrow(() -> new RuntimeException("Teacher not found"));

        return studentRepository.findByClassroomCode(teacher.getClassroomCode())
                .stream()
                .map(student -> {
                    StudentDashboardDTO dto = new StudentDashboardDTO();
                    dto.setId(student.getId());
                    dto.setName(student.getName());
                    dto.setRollNumber(student.getRollNumber());
                    dto.setEmail(student.getEmail());
                    dto.setPresentToday(
                            attendanceService.isStudentPresentToday(student)
                    );
                    return dto;
                })
                .collect(Collectors.toList());
    }


    @DeleteMapping("/delete-student/{id}")
    public ResponseEntity<?> deleteStudent(@PathVariable Long id) {

        Student student = studentRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Student not found"));

        attendanceRepository.deleteByStudent(student);
        studentRepository.delete(student);

        return ResponseEntity.ok("Student Deleted Successfully");
    }

    // Alias endpoint for frontend compatibility
    @DeleteMapping("/{id}")
    public ResponseEntity<?> deleteStudentAlias(@PathVariable Long id) {
        return deleteStudent(id);
    }

    //  ATTENDANCE OTP
    @PostMapping("/send-otp")
    public ResponseEntity<?> sendOtp() {
    // Send normal OTP to all students
    otpService.sendOtpToAllStudents();
    return ResponseEntity.ok().body(Map.of("message", "Normal OTP sent to all students successfully"));
    }

    // ===== Account deletion flow =====
    @PostMapping("/request-delete")
    public ResponseEntity<String> requestDelete(@RequestBody Map<String, String> body) {
        String email = body.get("email");
        if (email == null) return ResponseEntity.badRequest().body("Email required");

        Teacher teacher = teacherRepository.findByEmail(email)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid email"));

        String token = UUID.randomUUID().toString();
        teacher.setDeleteToken(token);
        teacher.setDeleteTokenExpiry(LocalDateTime.now().plusMinutes(30));
        teacherRepository.save(teacher);

        String deleteLink = "http://localhost:8080/api/teacher/verify-delete?token=" + token;
        emailService.sendMail(
                teacher.getEmail(),
                "Confirm account deletion",
                "Click to delete your account: " + deleteLink
        );
        System.out.println(deleteLink);
        return ResponseEntity.ok("Verification link sent to your email. Click it to confirm account deletion.");
    }

    @GetMapping("/verify-delete")
    public ResponseEntity<String> verifyDelete(@RequestParam String token) {
        Teacher teacher = teacherRepository.findByDeleteToken(token)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid token"));

        if (teacher.getDeleteTokenExpiry() == null || teacher.getDeleteTokenExpiry().isBefore(LocalDateTime.now())) {
            return ResponseEntity.badRequest().body("Token expired");
        }

        // Delete all students and their attendance records
        List<Student> students = studentRepository.findByClassroomCode(teacher.getClassroomCode());
        for (Student s : students) {
            attendanceRepository.deleteByStudent(s);
        }
        studentRepository.deleteAll(students);

        // Delete teacher account
        teacherRepository.delete(teacher);
        
        return ResponseEntity.ok("Account deleted successfully");
    }

    // ===== LOGOUT =====
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpSession session) {
        session.invalidate();
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "Logged out successfully"
        ));
    }
}

