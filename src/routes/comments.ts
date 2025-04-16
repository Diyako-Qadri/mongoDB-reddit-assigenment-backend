import { Request, Response, Router } from "express";
import { isValidObjectId, Types } from "mongoose";
import { Comment, Post } from "../models/post";
import { authenticate } from "../middlewares/authenticate";

const createComment = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      res.status(400).json({ message: "invalid post id" });
      return;
    }

    const post = await Post.findById(id);

    if (!post) {
      res.status(400).json({ message: "no post found" });
      return;
    }

    const { content } = req.body;

    if (content !== undefined && typeof content !== "string") {
      res.status(400).json({ message: "malformed content" });
      return;
    }

    post.comments.push({
      content,
      author: req.userId,
    });

    await post.save();
    res.status(201).json({ message: "comment created" });
  } catch (error) {
    console.log(error);
    res.status(500).send();
  }
};

const deleteComment = async (req: Request, res: Response) => {
  try {

    const { id, commentId } = req.params;

    if (!isValidObjectId(id)) {
      res.status(400).json({ message: "invalid post id" });
      return;
    }

    const post = await Post.findById(id);

    if (!post) {
      res.status(404).json({ message: "post not found" });
      return;
    }
    
    const comment = post.comments.id(commentId)

    if (
      post.author.toString() !== req.userId &&
      comment?.author.toString() !== req.userId
    ) {
      res
        .status(403)
        .json({ message: "you are not allowed to delete this comment" });
      return;
    }


    await comment?.deleteOne();
    await post.save()
    res.status(200).json({ message: "comment deleted" });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

export const commentsRouter = Router();

commentsRouter.post("/posts/:id/comment", authenticate, createComment);
commentsRouter.delete("/posts/:id/comment/:commentId", authenticate, deleteComment);