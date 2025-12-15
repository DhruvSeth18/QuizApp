package QuizApp.example.QuizApp.Controller;

import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.*;

import QuizApp.example.QuizApp.Utility.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.parameters.P;
import org.springframework.web.bind.annotation.*;

import QuizApp.example.QuizApp.Dao.QuestionDao;
import QuizApp.example.QuizApp.Dao.QuizDao;
import QuizApp.example.QuizApp.Model.QuestionAttempt;
import QuizApp.example.QuizApp.Model.Questions;
import QuizApp.example.QuizApp.Model.Quiz;
import QuizApp.example.QuizApp.Model.QuizAttempt;
import QuizApp.example.QuizApp.Model.User;
import QuizApp.example.QuizApp.Repository.QuizAttemptRepository;
import QuizApp.example.QuizApp.Repository.QuizRepository;
import QuizApp.example.QuizApp.Repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import QuizApp.example.QuizApp.Model.PassOrFail;

@RestController
@RequestMapping("/api/quiz")
@Slf4j
@CrossOrigin(origins = "http://localhost:5173")
public class QuizController {
    @Autowired
    private QuizAttemptRepository quizAttemptRepository;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private QuizRepository quizRepository;
    @Autowired
    private JwtUtil jwtUtil;

    @PostMapping("/createQuiz")
    public ResponseEntity<?> createQuiz(@RequestBody QuizDao quiz){
        try {
            Map<String, Object> map = new HashMap<>();
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();

            // Fetch userId from email
            Optional<User> userOpt = userRepository.findByEmail(email);
            String userId = userOpt.map(User::getId).orElse(null);

            // Validate quizDate and startTime
            LocalDateTime now = LocalDateTime.now();
            if (quiz.getQuizDate() == null || quiz.getStartTime() == null) {
                map.put("Message", "Quiz date and start time are required");
                return ResponseEntity.badRequest().body(map);
            }

            LocalDateTime quizStart = LocalDateTime.of(quiz.getQuizDate().toLocalDate(), quiz.getStartTime());
            if (quizStart.isBefore(now)) {
                map.put("Message", "Quiz start time must be in the future");
                return ResponseEntity.badRequest().body(map);
            }

            // Optional: validate endTime > startTime
            if (quiz.getEndTime() != null) {
                LocalDateTime quizEnd = LocalDateTime.of(quiz.getQuizDate().toLocalDate(), quiz.getEndTime());
                if (!quizEnd.isAfter(quizStart)) {
                    map.put("Message", "Quiz end time must be after start time");
                    return ResponseEntity.badRequest().body(map);
                }
            }

            Quiz quiz2 = new Quiz();
            quiz2.setQuizName(quiz.getQuizName());
            quiz2.setDuration(quiz.getDuration());
            quiz2.setDescription(quiz.getDescription());
            quiz2.setTotalQuestions(quiz.getTotalQuestions());
            quiz2.setDuration(quiz.getDuration());
            quiz2.setPassingScore((int) Math.ceil((quiz.getPassingPercentage()/100.0) * quiz.getTotalQuestions()));
            quiz2.setPassingPercentage(quiz.getPassingPercentage());
            quiz2.setQuizDate(quiz.getQuizDate());
            quiz2.setStartTime(quiz.getStartTime());
            quiz2.setEndTime(quiz.getEndTime());
            quiz2.setActive(true);
            quiz2.setCreatedAt(LocalDateTime.now());
            quiz2.setCreatedBy(userId);

            quizRepository.save(quiz2);

            map.put("message", "Quiz created successfully");
            map.put("status", true);
            map.put("quizId", quiz2.getId());

            return ResponseEntity.ok().body(map);

        } catch (Exception e) {
            log.error("Error occured : " + e.getMessage());
            return ResponseEntity.badRequest().body("Error occured : " + e.getMessage());
        }
    }

    @GetMapping("/myquizzes")
    public ResponseEntity<?> getMyQuizzes(@RequestHeader("Authorization") String authHeader) {
        try {
            Map<String, Object> map = new HashMap<>();

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                map.put("Message", "Authorization header missing or invalid");
                return ResponseEntity.status(401).body(map);
            }

            String token = authHeader.substring(7);  // Remove "Bearer "
            String userId = jwtUtil.extractUserId(token); // non-static call

            List<Quiz> myQuizzes = quizRepository.findAllByCreatedBy(userId);
            map.put("quizzes", myQuizzes);
            map.put("count", myQuizzes.size());

            return ResponseEntity.ok(map);

        } catch (Exception e) {
            Map<String, Object> map = new HashMap<>();
            map.put("Message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(map);
        }
    }

    @GetMapping("/test")
    public ResponseEntity<?> getSingleQuiz(@RequestParam String quizId) {
        try {
            Map<String, Object> response = new HashMap<>();

            if (quizId == null || quizId.isEmpty()) {
                response.put("message", "quizId is required");
                return ResponseEntity.badRequest().body(response);
            }

            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                response.put("message", "Quiz not found");
                return ResponseEntity.badRequest().body(response);
            }

            Quiz quiz = quizOpt.get();
            response.put("status", true);
            response.put("quiz", quiz);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> response = new HashMap<>();
            response.put("status", false);
            response.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }


    @GetMapping("/myquiz/{quizId}")
    public ResponseEntity<?> getSingleQuiz(
            @PathVariable String quizId,
            @RequestHeader("Authorization") String authHeader) {

        try {
            Map<String, Object> map = new HashMap<>();

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                map.put("Message", "Authorization header missing or invalid");
                return ResponseEntity.status(401).body(map);
            }

            // Token se userId extract karo
            String token = authHeader.substring(7);
            String userId = jwtUtil.extractUserId(token);

            // Quiz fetch karo
            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                map.put("Message", "Quiz not found");
                return ResponseEntity.badRequest().body(map);
            }

            Quiz quiz = quizOpt.get();

            // Validate karo ki quiz createdBy same user hai
            if (!quiz.getCreatedBy().equals(userId)) {
                map.put("Message", "You are not authorized to view this quiz");
                return ResponseEntity.status(403).body(map);
            }

            map.put("quiz", quiz);
            map.put("status", true);
            return ResponseEntity.ok(map);

        } catch (Exception e) {
            Map<String, Object> map = new HashMap<>();
            map.put("Message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(map);
        }
    }


    @PostMapping("/addQues")
    public ResponseEntity<?> addQues(
            @RequestBody QuestionDao questionDao,
            @RequestParam String quizId,
            @RequestHeader("Authorization") String authHeader) {

        try {
            Map<String, Object> map = new HashMap<>();

            if (quizId == null) {
                return ResponseEntity.badRequest().body("Please enter quiz");
            }

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                map.put("Message", "Authorization header missing or invalid");
                return ResponseEntity.status(401).body(map);
            }

            // Token se userId nikal lo
            String token = authHeader.substring(7);
            String userId = jwtUtil.extractUserId(token);

            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                return ResponseEntity.badRequest().body("Either quiz was expired or not found");
            }

            Quiz quiz = quizOpt.get();

            // Check if user is creator
            if (!quiz.getCreatedBy().equals(userId)) {
                map.put("Message", "You are not authorized to modify this quiz");
                return ResponseEntity.status(403).body(map);
            }

            int total = quiz.getTotalQuestions();
            List<Questions> existingQuestions = quiz.getQuestions();
            if (existingQuestions == null) {
                existingQuestions = new ArrayList<>();
            }

            // Check max limit
            if (existingQuestions.size() >= total) {
                return ResponseEntity.badRequest().body("You have already reached the max limit of " + total + " questions.");
            }

            // Check if same question already exists
            boolean questionExists = existingQuestions.stream()
                    .anyMatch(q -> q.getQuestionText().equalsIgnoreCase(questionDao.getQuestionText()));
            if (questionExists) {
                return ResponseEntity.badRequest().body("This question already exists in the quiz.");
            }

            // Add new question
            Questions questions = new Questions();
            questions.setId(UUID.randomUUID().toString());
            questions.setQuestionText(questionDao.getQuestionText());
            questions.setCorrectOption(questionDao.getCorrectOption());
            questions.setTimeLimit(questionDao.getTimeLimit());
            questions.setOptions(questionDao.getOptions());
            existingQuestions.add(questions);

            quiz.setQuestions(existingQuestions);
            quizRepository.save(quiz);

            map.put("Message","Question added successfully");
            return ResponseEntity.ok().body(map);

        } catch (Exception e) {
            log.error("Error occurred : " + e.getMessage());
            return ResponseEntity.badRequest().body("Error occurred : " + e.getMessage());
        }
    }

    @DeleteMapping("/deletequestion")
    public ResponseEntity<?> deleteQuestion(
            @RequestParam String quizId,
            @RequestHeader("Authorization") String authHeader,
            @RequestBody QuestionDao questionTextDao) {

        try {
            Map<String, Object> map = new HashMap<>();

            if (quizId == null || questionTextDao.getQuestionText() == null) {
                return ResponseEntity.badRequest().body("Quiz ID and Question text are required");
            }

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                map.put("Message", "Authorization header missing or invalid");
                return ResponseEntity.status(401).body(map);
            }

            // Extract userId from token
            String token = authHeader.substring(7);
            String userId = jwtUtil.extractUserId(token);

            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                return ResponseEntity.badRequest().body("Quiz not found");
            }

            Quiz quiz = quizOpt.get();

            // Check if user is the creator
            if (!quiz.getCreatedBy().equals(userId)) {
                map.put("Message", "You are not authorized to delete questions from this quiz");
                return ResponseEntity.status(403).body(map);
            }

            List<Questions> existingQuestions = quiz.getQuestions();
            if (existingQuestions == null || existingQuestions.isEmpty()) {
                return ResponseEntity.badRequest().body("No questions found in this quiz");
            }

            boolean removed = existingQuestions.removeIf(
                    q -> q.getQuestionText().equalsIgnoreCase(questionTextDao.getQuestionText())
            );

            if (!removed) {
                return ResponseEntity.badRequest().body("Question not found in this quiz");
            }

            quiz.setQuestions(existingQuestions);
            quizRepository.save(quiz);

            map.put("Message", "Question deleted successfully");
            return ResponseEntity.ok(map);

        } catch (Exception e) {
            log.error("Error occurred : " + e.getMessage());
            return ResponseEntity.badRequest().body("Something went wrong: " + e.getMessage());
        }
    }

    @PutMapping("/updatequiz")
    public ResponseEntity<?> updateQuiz(
            @RequestParam String quizId,
            @RequestHeader("Authorization") String authHeader,
            @RequestBody QuizDao updatedQuiz) {

        Map<String, Object> map = new HashMap<>();
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                map.put("Message", "Authorization header missing or invalid");
                return ResponseEntity.status(401).body(map);
            }

            String token = authHeader.substring(7);
            String userId = jwtUtil.extractUserId(token);

            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                map.put("Message", "Quiz not found with given ID");
                return ResponseEntity.badRequest().body(map);
            }

            Quiz quiz = quizOpt.get();

            // Owner validation
            if (!quiz.getCreatedBy().equals(userId)) {
                map.put("Message", "You are not authorized to update this quiz");
                return ResponseEntity.status(403).body(map);
            }

            // Validation: startTime & endTime must exist first
            if (updatedQuiz.getStartTime() != null && updatedQuiz.getEndTime() != null) {
                LocalTime start = updatedQuiz.getStartTime();
                LocalTime end = updatedQuiz.getEndTime();
                if (end.isBefore(start) || end.equals(start)) {
                    map.put("Message", "End time must be after start time");
                    return ResponseEntity.badRequest().body(map);
                }

                long diffMinutes = java.time.Duration.between(start, end).toMinutes();
                if (updatedQuiz.getDuration() * 60 > diffMinutes) {
                    map.put("Message", "Duration cannot exceed the difference between start and end time");
                    return ResponseEntity.badRequest().body(map);
                }

                quiz.setStartTime(start);
                quiz.setEndTime(end);
            } else if (updatedQuiz.getStartTime() != null && quiz.getEndTime() != null) {
                LocalTime start = updatedQuiz.getStartTime();
                LocalTime end = quiz.getEndTime();
                if (end.isBefore(start) || end.equals(start)) {
                    map.put("Message", "Start time cannot be after existing end time");
                    return ResponseEntity.badRequest().body(map);
                }

                long diffMinutes = java.time.Duration.between(start, end).toMinutes();
                if (updatedQuiz.getDuration() * 60 > diffMinutes) {
                    map.put("Message", "Duration cannot exceed the difference between start and end time");
                    return ResponseEntity.badRequest().body(map);
                }

                quiz.setStartTime(start);
            } else if (updatedQuiz.getEndTime() != null && quiz.getStartTime() != null) {
                LocalTime start = quiz.getStartTime();
                LocalTime end = updatedQuiz.getEndTime();
                if (end.isBefore(start) || end.equals(start)) {
                    map.put("Message", "End time cannot be before existing start time");
                    return ResponseEntity.badRequest().body(map);
                }

                long diffMinutes = java.time.Duration.between(start, end).toMinutes();
                if (updatedQuiz.getDuration() * 60 > diffMinutes) {
                    map.put("Message", "Duration cannot exceed the difference between start and end time");
                    return ResponseEntity.badRequest().body(map);
                }

                quiz.setEndTime(end);
            }

            // Update other fields if provided
            if (updatedQuiz.getQuizName() != null) quiz.setQuizName(updatedQuiz.getQuizName());
            if (updatedQuiz.getDescription() != null) quiz.setDescription(updatedQuiz.getDescription());
            if (updatedQuiz.getDuration() != 0) quiz.setDuration(updatedQuiz.getDuration());
            if (updatedQuiz.getTotalQuestions() != 0) {
                quiz.setTotalQuestions(updatedQuiz.getTotalQuestions());
                quiz.setTotalMarks(updatedQuiz.getTotalQuestions());
            }
            if (updatedQuiz.getPassingPercentage() != 0) {
                quiz.setPassingPercentage(updatedQuiz.getPassingPercentage());
                quiz.setPassingScore((int) Math.ceil(
                        (updatedQuiz.getPassingPercentage() / 100.0) *
                                (updatedQuiz.getTotalQuestions() != 0 ? updatedQuiz.getTotalQuestions() : quiz.getTotalMarks())
                ));
            }
            if (updatedQuiz.getQuizDate() != null) quiz.setQuizDate(updatedQuiz.getQuizDate());

            quiz.setUpdatedAt(LocalDateTime.now());
            quizRepository.save(quiz);

            map.put("Message", "Quiz updated successfully");
            map.put("quiz", quiz);
            map.put("status", true);
            return ResponseEntity.ok(map);

        } catch (Exception e) {
            log.error("Error occurred: " + e.getMessage());
            map.put("Message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(map);
        }
    }

    @PostMapping("/startquiz")
    public ResponseEntity<?> startQuiz(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        try {
            Map<String, Object> response = new HashMap<>();

            String jwtToken = token.startsWith("Bearer ")
                    ? token.substring(7)
                    : token;

            String userId = jwtUtil.extractUserId(jwtToken);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Quiz quiz = quizRepository.findById(quizId)
                    .orElseThrow(() -> new RuntimeException("Quiz not found"));

            /* ================= TIME WINDOW CHECK ================= */
            LocalTime now = LocalTime.now();
            if (quiz.getStartTime() != null && quiz.getEndTime() != null) {
                if (now.isBefore(quiz.getStartTime())) {
                    return ResponseEntity.badRequest().body("Quiz has not started yet");
                }
                if (now.isAfter(quiz.getEndTime())) {
                    return ResponseEntity.badRequest().body("Quiz time is over");
                }
            }

            QuizAttempt attempt = quizAttemptRepository
                    .findByUserIdAndQuizId(userId, quizId)
                    .orElseThrow(() -> new RuntimeException("User not registered for this quiz"));

            /* ================= ALREADY COMPLETED ================= */
            if ("COMPLETED".equalsIgnoreCase(attempt.getStatus())) {
                return ResponseEntity.badRequest()
                        .body("Quiz already submitted");
            }

            /* ================= RESUME CASE ================= */
            if ("IN_PROGRESS".equalsIgnoreCase(attempt.getStatus())) {
                response.put("status", true);
                response.put("message", "Quiz already in progress");
                response.put("attempt", attempt);
                response.put("user", user);
                return ResponseEntity.ok(response);
            }

            /* ================= SHUFFLE QUESTIONS ================= */
            List<Questions> originalQuestions =
                    quiz.getQuestions() != null ? quiz.getQuestions() : new ArrayList<>();

            List<Questions> shuffledQuestions = new ArrayList<>(originalQuestions);
            Collections.shuffle(shuffledQuestions);

            shuffledQuestions.forEach(q -> {
                if (q.getOptions() != null) {
                    Collections.shuffle(q.getOptions());
                }
            });

            /* ================= BUILD QUESTION ATTEMPTS ================= */
            List<QuestionAttempt> questionAttempts = new ArrayList<>();
            for (Questions q : shuffledQuestions) {
                QuestionAttempt qa = new QuestionAttempt();
                qa.setQuestionId(q.getId());
                qa.setSelectedOption(null);
                qa.setCorrect(false);
                questionAttempts.add(qa);
            }

            /* ================= UPDATE ATTEMPT ================= */
            attempt.setStatus("IN_PROGRESS");
            attempt.setQuizStartTime(LocalDateTime.now());

            attempt.setShuffledQuestions(shuffledQuestions);
            attempt.setAttemptedQuestions(questionAttempts);

            attempt.setDuration(quiz.getDuration());
            attempt.setNumberOfQuestion(shuffledQuestions.size());
            attempt.setPercentage(0.0);
            attempt.setMarksObtained(0);

            QuizAttempt savedAttempt = quizAttemptRepository.save(attempt);

            /* ================= RESPONSE ================= */
            response.put("status", true);
            response.put("message", "Quiz started successfully");
            response.put("attempt", savedAttempt);
            response.put("user", user);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @DeleteMapping("/deletequiz")
    public ResponseEntity<?> deleteQuiz(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        try {
            Map<String, Object> response = new HashMap<>();

            // JWT se userId nikal lo (optional, agar admin check karna ho)
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = jwtUtil.extractUserId(jwtToken);

            // Quiz exist check
            Quiz quiz = quizRepository.findById(quizId)
                    .orElseThrow(() -> new RuntimeException("Quiz not found"));

            // Delete all quiz attempts
            quizAttemptRepository.deleteByQuizId(quizId);

            quizRepository.deleteById(quizId);

            response.put("status", true);
            response.put("message", "Quiz and all its attempts deleted successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/participants")
    public ResponseEntity<?> getQuizParticipants(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        try {
            Map<String, Object> response = new HashMap<>();

            // ================= JWT =================
            String jwtToken = token.startsWith("Bearer ")
                    ? token.substring(7)
                    : token;

            String requesterId = jwtUtil.extractUserId(jwtToken);

            // ================= QUIZ CHECK =================
            Quiz quiz = quizRepository.findById(quizId)
                    .orElseThrow(() -> new RuntimeException("Quiz not found"));

            // (Optional) sirf creator ko allow karna ho
            // if (!quiz.getCreatedBy().equals(requesterId)) {
            //     throw new RuntimeException("You are not authorized to view participants");
            // }

            // ================= FETCH ATTEMPTS =================
            List<QuizAttempt> attempts = quizAttemptRepository.findAllByQuizId(quizId);

            List<Map<String, Object>> participants = new ArrayList<>();

            for (QuizAttempt attempt : attempts) {

                // ================= FETCH USER =================
                User user = userRepository.findById(attempt.getUserId())
                        .orElse(null); // user delete ho gaya ho to bhi crash na ho

                Map<String, Object> data = new HashMap<>();

                data.put("userId", attempt.getUserId());
                data.put("name", user != null ? user.getUsername() : "Unknown User");
                data.put("email", user != null ? user.getEmail() : "N/A");

                data.put("marksObtained", attempt.getMarksObtained());
                data.put("numberOfQuestion", attempt.getNumberOfQuestion());
                data.put("percentage", attempt.getPercentage());

                data.put("result", attempt.getResult()); // PASS / FAIL
                data.put("status", attempt.getStatus()); // COMPLETED / IN_PROGRESS / REGISTERED

                data.put("attemptedAt", attempt.getAttemptedAt());
                data.put("submittedAt", attempt.getSubmittedAt());

                participants.add(data);
            }

            // ================= RESPONSE =================
            response.put("status", true);
            response.put("quizId", quiz.getId());
            response.put("quizName", quiz.getQuizName());
            response.put("totalParticipants", participants.size());
            response.put("participants", participants);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @PostMapping("/submitQuiz")
    public ResponseEntity<?> submitQuiz(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        try {
            Map<String, Object> response = new HashMap<>();

            String jwtToken = token.startsWith("Bearer ")
                    ? token.substring(7)
                    : token;

            String userId = jwtUtil.extractUserId(jwtToken);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            Quiz quiz = quizRepository.findById(quizId)
                    .orElseThrow(() -> new RuntimeException("Quiz not found"));

            QuizAttempt attempt = quizAttemptRepository
                    .findByUserIdAndQuizId(userId, quizId)
                    .orElseThrow(() -> new RuntimeException("Quiz attempt not found"));

            /* ================= VALIDATIONS ================= */
            if (!"IN_PROGRESS".equalsIgnoreCase(attempt.getStatus())) {
                return ResponseEntity.badRequest()
                        .body("Quiz is not in progress");
            }

            /* ================= EVALUATION ================= */
            int correctCount = 0;

            List<QuestionAttempt> attemptedQuestions = attempt.getAttemptedQuestions();
            List<Questions> questions = attempt.getShuffledQuestions();

            Map<String, String> correctAnswerMap = new HashMap<>();
            for (Questions q : questions) {
                correctAnswerMap.put(q.getId(), q.getCorrectOption());
            }

            for (QuestionAttempt qa : attemptedQuestions) {
                String correctOption = correctAnswerMap.get(qa.getQuestionId());

                if (qa.getSelectedOption() != null &&
                        qa.getSelectedOption().equals(correctOption)) {

                    qa.setCorrect(true);
                    correctCount++;
                } else {
                    qa.setCorrect(false);
                }
            }

            /* ================= RESULT CALCULATION ================= */
            int totalQuestions = attempt.getNumberOfQuestion();
            double percentage = (correctCount * 100.0) / totalQuestions;

            attempt.setMarksObtained(correctCount);
            attempt.setPercentage(percentage);
            attempt.setSubmittedAt(LocalDateTime.now());
            attempt.setStatus("COMPLETED");
            attempt.setEndQuiz(true);

            if (percentage >= quiz.getPassingPercentage()) {
                attempt.setPassOrFail(PassOrFail.PASS);
                attempt.setResult("PASS");
            } else {
                attempt.setPassOrFail(PassOrFail.FAIL);
                attempt.setResult("FAIL");
            }

            QuizAttempt savedAttempt = quizAttemptRepository.save(attempt);

            /* ================= RESPONSE ================= */
            response.put("status", true);
            response.put("message", "Quiz submitted successfully");
            response.put("result", savedAttempt.getResult());
            response.put("percentage", savedAttempt.getPercentage());
            response.put("marksObtained", savedAttempt.getMarksObtained());
            response.put("attempt", savedAttempt);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }





    @GetMapping("/user/allQuizzes")
    public ResponseEntity<?> getAllUserQuizzes(@RequestParam String userId) {
        try {
            Map<String, Object> response = new HashMap<>();

            // ✅ Fetch user
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                return ResponseEntity.badRequest().body("User not found");
            }

            User user = userOpt.get();

            // ✅ Attempted quizzes
            List<String> attemptedQuizIds = user.getAttemptedQuiz();
            List<Quiz> attemptedQuizzes = (attemptedQuizIds != null && !attemptedQuizIds.isEmpty())
                    ? quizRepository.findAllById(attemptedQuizIds)
                    : new ArrayList<>();
            
            // ✅ Created quizzes
            List<Quiz> createdQuizzes = quizRepository.findAllByCreatedBy(userId);

            // ✅ Optional: Upcoming quizzes (active & future)
            List<Quiz> upcomingQuizzes = quizRepository.findAll().stream()
                    .filter(q -> q.isActive() && q.getQuizDate() != null && q.getQuizDate().isAfter(LocalDateTime.now()))
                    .toList();

            // ✅ Build response
            response.put("status", true);
            response.put("attemptedQuizzes", attemptedQuizzes);
            response.put("createdQuizzes", createdQuizzes);
            response.put("upcomingQuizzes", upcomingQuizzes);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }


    @PostMapping("/registerQuiz")
    public ResponseEntity<?> registerQuiz(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {
        try {
            Map<String, Object> response = new HashMap<>();

            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = jwtUtil.extractUserId(jwtToken);

            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                response.put("status", false);
                response.put("message", "Quiz not found");
                return ResponseEntity.badRequest().body(response);
            }
            Quiz quiz = quizOpt.get();

            // ✅ CHECK IF ACTUAL QUESTIONS MATCH numberOfQuestion
            List<Questions> actualQuestions = quiz.getQuestions() != null ? quiz.getQuestions() : new ArrayList<>();
            if (quiz.getTotalQuestions() == 0 || actualQuestions.size() < quiz.getTotalQuestions()) {
                response.put("status", false);
                response.put("message", "Quiz cannot be registered because not enough questions are added");
                return ResponseEntity.badRequest().body(response);
            }

            Optional<QuizAttempt> existingAttempt = quizAttemptRepository.findByUserIdAndQuizId(userId, quizId);
            if (existingAttempt.isPresent()) {
                String status = existingAttempt.get().getStatus();
                if ("REGISTERED".equalsIgnoreCase(status)) {
                    response.put("status", true);
                    response.put("message", "User already registered for this quiz");
                    response.put("attempt", existingAttempt.get());
                    return ResponseEntity.ok(response);
                } else {
                    response.put("status", false);
                    response.put("message", "User already attempted or started this quiz");
                    return ResponseEntity.badRequest().body(response);
                }
            }

            // ✅ CREATE REGISTERED ATTEMPT
            QuizAttempt quizAttempt = new QuizAttempt();
            quizAttempt.setUserId(userId);
            quizAttempt.setQuizId(quizId);
            quizAttempt.setStatus("REGISTERED");
            quizAttempt.setMarksObtained(0);
            quizAttempt.setAttemptedAt(LocalDateTime.now());
            quizAttempt.setStartTime(quiz.getStartTime());
            quizAttempt.setEndTime(quiz.getEndTime());

            QuizAttempt savedAttempt = quizAttemptRepository.save(quizAttempt);

            // ✅ UPDATE QUIZ attemptedUsersId
            List<String> attemptedUsers = quiz.getAttemptedUsersId();
            if (attemptedUsers == null) attemptedUsers = new ArrayList<>();
            if (!attemptedUsers.contains(userId)) attemptedUsers.add(userId);
            quiz.setAttemptedUsersId(attemptedUsers);
            quizRepository.save(quiz);

            response.put("status", true);
            response.put("message", "User successfully registered for the quiz");
            response.put("attempt", savedAttempt);
            response.put("quizDetails", quiz);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }



    @GetMapping("/check")
    public ResponseEntity<Map<String, Object>> checkIfQuizExist(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        Map<String, Object> response = new HashMap<>();

        try {
            // Extract userId from JWT
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = jwtUtil.extractUserId(jwtToken);

            // Fetch quiz
            Optional<Quiz> quizOpt = quizRepository.findById(quizId);
            if (!quizOpt.isPresent()) {
                response.put("status", false);
                response.put("message", "Quiz not found");
                return ResponseEntity.badRequest().body(response);
            }

            Quiz quiz = quizOpt.get();

            // Check if user is the creator
            boolean isCreator = quiz.getCreatedBy() != null && quiz.getCreatedBy().equals(userId);

            // Fetch existing QuizAttempt
            Optional<QuizAttempt> quizAttemptOpt = quizAttemptRepository.findByUserIdAndQuizId(userId, quizId);

            if (quizAttemptOpt.isPresent()) {
                QuizAttempt attempt = quizAttemptOpt.get();

                // ✅ Corrected logic for isRegistered
                boolean isRegistered = "REGISTERED".equalsIgnoreCase(attempt.getStatus())
                        || "IN_PROGRESS".equalsIgnoreCase(attempt.getStatus())
                        || "COMPLETED".equalsIgnoreCase(attempt.getStatus());

                response.put("status", true);
                response.put("isRegistered", isRegistered);
                response.put("currentStatus", attempt.getStatus());
                response.put("isCreator", isCreator);
                response.put("attemptId", attempt.getId());
                response.put("message", isRegistered
                        ? "User already attempted or started this quiz"
                        : "User has not registered for this quiz yet");

                return ResponseEntity.ok(response);
            } else {
                response.put("status", true);
                response.put("isRegistered", false);
                response.put("currentStatus", "NONE");
                response.put("isCreator", isCreator);
                response.put("message", isCreator
                        ? "User is the creator of this quiz"
                        : "User has not registered for this quiz yet");
                return ResponseEntity.ok(response);
            }

        } catch (Exception e) {
            response.put("status", false);
            response.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/attempted/quizzes")
    public ResponseEntity<?> getUserAttemptedQuizzes(
            @RequestHeader("Authorization") String token) {

        try {
            Map<String, Object> response = new HashMap<>();

            String jwtToken = token.startsWith("Bearer ")
                    ? token.substring(7)
                    : token;

            String userId = jwtUtil.extractUserId(jwtToken);

            User user = userRepository.findById(userId)
                    .orElseThrow(() -> new RuntimeException("User not found"));

            List<QuizAttempt> attempts =
                    quizAttemptRepository.findByUserId(userId);

            response.put("status", true);
            response.put("message", "Attempted quizzes fetched successfully");
            response.put("totalAttempts", attempts.size());
            response.put("attempts", attempts);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }


    @PostMapping("/saveanswer")
    public ResponseEntity<Map<String, Object>> saveAnswer(
            @RequestParam String attemptId,
            @RequestParam String questionId,
            @RequestParam String selectedOption) {

        Map<String, Object> response = new HashMap<>();

        try {
            QuizAttempt attempt = quizAttemptRepository.findById(attemptId)
                    .orElseThrow(() -> new RuntimeException("Quiz attempt not found"));

            List<QuestionAttempt> qAttempts = attempt.getAttemptedQuestions();
            if (qAttempts == null) {
                qAttempts = new ArrayList<>();
            }

            QuestionAttempt existing = qAttempts.stream()
                    .filter(q -> q.getQuestionId().equals(questionId))
                    .findFirst()
                    .orElse(null);

            if (existing != null) {
                existing.setSelectedOption(selectedOption);
            } else {
                QuestionAttempt newQ = new QuestionAttempt();
                newQ.setQuestionId(questionId);
                newQ.setSelectedOption(selectedOption);
                qAttempts.add(newQ);
            }

            attempt.setAttemptedQuestions(qAttempts);
            QuizAttempt updatedAttempt = quizAttemptRepository.save(attempt);

            response.put("status", "success");
            response.put("message", "Answer submitted successfully");
            response.put("attempt", updatedAttempt);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.status(500).body(response);
        }
    }


    @GetMapping("/attempt")
    public ResponseEntity<Map<String, Object>> getQuizAttempt(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizId) {

        Map<String, Object> response = new HashMap<>();

        try {
            // 🔹 Extract JWT userId from token
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = jwtUtil.extractUserId(jwtToken);

            // 🔹 Fetch attempt
            Optional<QuizAttempt> attemptOpt = quizAttemptRepository.findByUserIdAndQuizId(userId, quizId);
            if (!attemptOpt.isPresent()) {
                response.put("status", false);
                response.put("message", "Quiz attempt not found for given user and quiz");
                return ResponseEntity.status(404).body(response);
            }

            QuizAttempt attempt = attemptOpt.get();

            // 🔹 Fetch user details
            Optional<User> userOpt = userRepository.findById(userId);
            if (!userOpt.isPresent()) {
                response.put("status", false);
                response.put("message", "User not found");
                return ResponseEntity.status(404).body(response);
            }

            User user = userOpt.get();

            // ✅ Prepare clean response
            response.put("status", true);
            response.put("message", "Quiz attempt fetched successfully");
            response.put("quizAttempt", attempt);
            response.put("user", user);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("status", false);
            response.put("message", "Something went wrong: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }




    @PostMapping("/disturbanceDetected")
    public ResponseEntity<?> disturbanceDetected(@RequestParam String attemptId){
        try {
            Map<String, Object> map = new HashMap<>();
            Optional<QuizAttempt> attempt = quizAttemptRepository.findById(attemptId);
            int totalDisturbance = attempt.get().getTotalDisturbance();
            int updatedDisturbance = totalDisturbance+=1;
            attempt.get().setTotalDisturbance(updatedDisturbance);
            if(updatedDisturbance>=5){
                quizAttemptRepository.save(attempt.get());
                completeQuiz(attemptId);
                // map.put("DisturbanceMessage", "Quiz completed")
                return ResponseEntity.ok("Quiz completed successfully");
            }
            quizAttemptRepository.save(attempt.get());

            map.put("Message", "You have only : " + (5 - totalDisturbance) + "attempts.");
            return ResponseEntity.ok(map);

        } catch (Exception e) {
            log.error("Error occured : "+e.getMessage());
            return ResponseEntity.badRequest().body("Something went wrong : "+e.getMessage());
        }
    }



   @PostMapping("/completequiz")
public ResponseEntity<?> completeQuiz(@RequestParam String attemptId) {
    try {
        Map<String, Object> map = new HashMap<>();
    QuizAttempt attempt = quizAttemptRepository.findById(attemptId)
            .orElseThrow(() -> new RuntimeException("Attempt not found"));

   
    if ("COMPLETED".equalsIgnoreCase(attempt.getStatus())) {
        return ResponseEntity.badRequest().body("Quiz already completed");
    }

    String quizId = attempt.getQuizId();
    String userId = attempt.getUserId();
    Optional<User> user = userRepository.findById(userId);
    Optional<Quiz> quiz = quizRepository.findById(quizId);

    if (!quiz.isPresent()) {
        return ResponseEntity.badRequest().body("Quiz not found");
    }

    List<Questions> actualQuestions = quiz.get().getQuestions();
    int marks = 0;

    for (QuestionAttempt qa : attempt.getAttemptedQuestions()) {
        Questions actualQ = actualQuestions.stream()
                .filter(q -> q.getId().equals(qa.getQuestionId()))
                .findFirst()
                .orElse(null);

        if (actualQ != null) {
            if (qa.getSelectedOption() != null 
                && qa.getSelectedOption().equals(actualQ.getCorrectOption())) {
                marks++;
                qa.setCorrect(true);
            } else {
                qa.setCorrect(false);
            }
        }
    }
    if(marks>=quiz.get().getPassingScore()){
        attempt.setResult("PASS");
    }
    else{
        attempt.setResult("FAIL");
    }
    attempt.setMarksObtained(marks);
    attempt.setStatus("COMPLETED");
    attempt.setSubmittedAt(LocalDateTime.now());
    List<String> quizes = user.get().getAttemptedQuiz();
    if(quizes==null){
        quizes=new ArrayList<>();
    }
    quizes.add(quizId);
    user.get().setAttemptedQuiz(quizes);
    userRepository.save(user.get());
    quizAttemptRepository.save(attempt);
    map.put("Message", attempt);
    return ResponseEntity.ok(map);
    } catch (Exception e) {
        log.error("Error occured : ", e.getMessage());
        return ResponseEntity.badRequest().body("Error occured : "+e.getMessage());
    }
}

    @DeleteMapping("/deleteQuiz")
    public ResponseEntity<?> deleteQuiz(@RequestParam String quizId){
        try {
            Optional<Quiz> quiz = quizRepository.findById(quizId);
            Map<String, Object> map = new HashMap<>();
            if(!quiz.isPresent()){
                return ResponseEntity.badRequest().body("Quiz not found");
            }
            quizRepository.deleteById(quizId);
            map.put("Message", "Quiz deleted successfully");
            return ResponseEntity.ok().body(map);

        } catch (Exception e) {
            log.error("Error occured : "+e.getMessage());
            return ResponseEntity.badRequest().body("Something went wrong : "+e.getMessage());
        }
    }
    @GetMapping("/attemptedQuiz")
    public ResponseEntity<?> attemptedQuiz(@RequestParam String userId) {
    try {
        Optional<User> userOpt = userRepository.findById(userId);
        Map<String, Object> map = new HashMap<>();
        if (!userOpt.isPresent()) {
            return ResponseEntity.badRequest().body("User not found");
        }

        User user = userOpt.get();
        List<String> quizIds = user.getAttemptedQuiz();

        if (quizIds == null || quizIds.isEmpty()) {
            map.put("Message", "No attempted quizzes found");
            return ResponseEntity.ok().body(map);
        }

        List<Quiz> attemptedQuizzes = quizRepository.findAllById(quizIds);
        map.put("status",true);
        map.put("Message", attemptedQuizzes);
        return ResponseEntity.ok(map);

    } catch (Exception e) {
        log.error("Error occurred : " + e.getMessage());
        return ResponseEntity.badRequest().body("Something went wrong : " + e.getMessage());
    }
}

    @GetMapping("/findQuiz")
    public ResponseEntity<?> findQuiz(@RequestParam String quizId){
        try {
            Map<String, Object> map = new HashMap<>();
            Optional<Quiz> quiz = quizRepository.findById(quizId);
            if(!quiz.isPresent()){
                map.put("Message", "Quiz not found");
                return ResponseEntity.badRequest().body(map);
            }
            map.put("Message", quiz.get());
            return ResponseEntity.ok().body(map);
        } catch (Exception e) {
            log.error("Error occured : "+e.getMessage());
            return ResponseEntity.badRequest().body("Something went wrong : "+e.getMessage());
        }
    }
    
    @PostMapping("/submit-answer")
    public ResponseEntity<?> submitAnswer(
            @RequestHeader("Authorization") String token,
            @RequestParam String quizAttemptId,
            @RequestParam String questionId,
            @RequestParam String selectedOption) {

        try {
            // 🔹 Extract userId from JWT token
            String jwtToken = token.startsWith("Bearer ") ? token.substring(7) : token;
            String userId = jwtUtil.extractUserId(jwtToken);

            // 🔹 Get QuizAttempt
            QuizAttempt attempt = quizAttemptRepository.findById(quizAttemptId)
                    .orElseThrow(() -> new RuntimeException("QuizAttempt not found"));

            // 🔹 Update selectedOption in shuffledQuestions
            attempt.getShuffledQuestions().forEach(q -> {
                if (q.getId().equals(questionId)) {
                    q.setSelectedOption(selectedOption);
                }
            });

            // 🔹 Update or add in attemptedQuestions
            boolean found = false;
            for (QuestionAttempt qa : attempt.getAttemptedQuestions()) {
                if (qa.getQuestionId().equals(questionId)) {
                    qa.setSelectedOption(selectedOption);
                    found = true;
                    break;
                }
            }
            if (!found) {
                QuestionAttempt qa = new QuestionAttempt();
                qa.setQuestionId(questionId);
                qa.setSelectedOption(selectedOption);
                qa.setCorrect(false); // backend se correct evaluation later
                attempt.getAttemptedQuestions().add(qa);
            }

            // 🔹 Save QuizAttempt
            QuizAttempt savedAttempt = quizAttemptRepository.save(attempt);

            // 🔹 Response
            Map<String, Object> response = new HashMap<>();
            response.put("status", true);
            response.put("message", "Answer submitted successfully");
            response.put("attempt", savedAttempt);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", false);
            error.put("message", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }


}
