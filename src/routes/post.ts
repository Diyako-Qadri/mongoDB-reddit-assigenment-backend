import { Router, type Request, type Response } from 'express';
import { isValidObjectId, ObjectId } from 'mongoose';

import { Post } from '../models/post';
import { authenticate } from '../middlewares/authenticate';

type AuthorWithUsername = {
  _id: ObjectId;
  username: string;
};

const getPosts = async (req: Request, res: Response) => {
  try {
    const limit = parseInt(req.query.limit?.toString() || '10');
    const page = parseInt(req.query.page?.toString() || '1');

    if (isNaN(page) || isNaN(limit)) {
      res.status(400).json({
        message: 'limit and page has to be valid numbers',
      });
      return;
    }

    const posts = await Post.aggregate([
      {
        $addFields: {
          sortValue: {
            $divide: [
              {
                $add: ['$score', 1],
              },
              {
                $pow: [
                  {
                    $add: [
                      {
                        $divide: [
                          { $subtract: [new Date(), '$createdAt'] },
                          1000 * 60 * 60,
                        ],
                      },
                      1,
                    ],
                  },
                  1.5,
                ],
              },
            ],
          },
        },
      },
      { $sort: { sortValue: -1 } },
      { $skip: limit * (page - 1) },
      { $limit: limit },
      {
        $lookup: {
          from: 'users',
          localField: 'author',
          foreignField: '_id',
          pipeline: [
            {
              $project: {
                username: 1,
              },
            },
          ],
          as: 'author',
        },
      },
      { $unwind: '$author' },
    ]);

    const responsePosts = posts.map(post => {
      const author = post.author as unknown as AuthorWithUsername;

      return {
        id: post._id,
        title: post.title,
        comments: post.comments,
        author: {
          username: author.username,
        },
        score: post.score,
        upvotes: post.upvotes,
        downvotes: post.downvotes,
      };
    });

    const totalCount = await Post.countDocuments();
    const totalPages = Math.ceil(totalCount / limit);

    res.status(200).json({
      posts: responsePosts,
      nextPage: page + 1 <= totalPages ? page + 1 : null,
    });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

const getPost = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      res.status(400).json({ message: 'invalid post id' });
      return;
    }

    const post = await Post.findById(id)
      .populate('author', 'username')
      .populate('comments.author', 'username');

    if (!post) {
      res.status(404).json({ message: 'post not found' });
      return;
    }

    const author = post.author as unknown as AuthorWithUsername;

    res.status(200).json({
      id: post._id,
      title: post.title,
      content: post.content,
      comments: post.comments,
      author: {
        id: author._id,
        username: author.username,
      },
    });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

const createPost = async (req: Request, res: Response) => {
  try {
    const { title, content } = req.body;

    if (!title || typeof title !== 'string') {
      res.status(400).json({ message: 'malformed title' });
      return;
    }

    if (content !== undefined && typeof content !== 'string') {
      res.status(400).json({ message: 'malformed content' });
      return;
    }

    const post = await Post.create({
      title,
      content,
      author: req.userId,
    });

    res.status(201).json({ id: post._id });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

const deletePost = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      res.status(400).json({ message: 'invalid post id' });
      return;
    }

    const post = await Post.findById(id);

    if (!post) {
      res.status(404).json({ message: 'post not found' });
      return;
    }

    if (post.author.toString() !== req.userId) {
      res
        .status(403)
        .json({ message: 'you are not allowed to delete this post' });
      return;
    }

    await post.deleteOne();
    res.status(200).json({ message: 'post deleted' });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

const editPost = async (req: Request, res: Response) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      res.status(400).json({ message: 'invalid post id' });
      return;
    }

    const post = await Post.findById(id);

    if (!post) {
      res.status(404).json({ message: 'post not found' });
      return;
    }

    if (post.author.toString() !== req.userId) {
      res
        .status(403)
        .json({ message: 'you are not allowed to edit this post' });
      return;
    }

    const { title, content } = req.body;

    if (title !== undefined && typeof title !== 'string') {
      res.status(400).json({ message: 'malformed title' });
      return;
    }

    if (content !== undefined && typeof content !== 'string') {
      res.status(400).json({ message: 'malformed content' });
      return;
    }

    await post.updateOne({
      title,
      content,
    });

    res.status(200).json({ message: 'post updated' });
  } catch (error) {
    console.error(error);
    res.status(500).send();
  }
};

export const postRouter = Router();

postRouter.get('/posts', getPosts);
postRouter.get('/posts/:id', getPost);
postRouter.post('/posts', authenticate, createPost);
postRouter.delete('/posts/:id', authenticate, deletePost);
postRouter.put('/posts/:id', authenticate, editPost);
