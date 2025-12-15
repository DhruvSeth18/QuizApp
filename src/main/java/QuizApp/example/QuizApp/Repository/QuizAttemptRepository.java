package QuizApp.example.QuizApp.Repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.mongodb.repository.MongoRepository;

import QuizApp.example.QuizApp.Model.QuizAttempt;
import org.springframework.transaction.annotation.Transactional;

public interface QuizAttemptRepository extends MongoRepository<QuizAttempt,String> {

    Optional<QuizAttempt> findByUserIdAndQuizIdAndStatus(String userId, String quizId, String string);
    List<QuizAttempt> findByUserId(String userId);
    Optional<QuizAttempt> findByUserIdAndQuizId(String userId, String quizId);
    List<QuizAttempt> findAllByQuizId(String quizId);
    @Transactional
    void deleteByQuizId(String quizId);
    
}
